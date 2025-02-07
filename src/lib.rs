use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use axum::{Json, RequestPartsExt};
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use axum_extra::typed_header::TypedHeaderRejection;
use axum_extra::TypedHeader;
use jsonwebtoken::{decode, decode_header, Validation};
use jwt::DecodingKey;
use jwt::jwk::{AlgorithmParameters, JwkSet};
use serde::{Deserialize, Serialize};
use reqwest;
use serde_json::json;
use tokio::sync::RwLock;
use thiserror::Error;
use tracing::{error, info, instrument, trace, warn};

extern crate jsonwebtoken as jwt;
extern crate jsonwebkey as jwk;

#[derive(Debug)]
#[derive(Deserialize)]
struct OIDCDiscoveryDocument {
    pub jwks_uri: String,
}


pub struct JwksRepository {
    issuer_uri: String,
    keys: HashMap<String, DecodingKey>,
}

#[derive(Debug)]
#[derive(Deserialize)]
pub struct OIDCJwksResponse {
    pub keys: Vec<OIDCJwksRepresentation>,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub struct OIDCJwksRepresentation {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    pub r#use: String,
    pub e: Option<String>,
    pub n: Option<String>,
}


impl JwksRepository {
    pub fn new(issuer: &str) -> Self {
        Self { issuer_uri: issuer.to_string(), keys: HashMap::new() }
    }
    pub fn get_key(&self, kid: String) -> Option<DecodingKey> {
        self.keys.get(&kid).map(|key| key.clone())

    }

    #[instrument (name = "fetching oauth keys", skip(self))]
    pub async fn fetch_keys(&mut self) -> Result<(), OIDCError> {
        if !self.keys.is_empty() {
            trace!("Keys already fetched");
            return Ok(());
        }
        let well_known_uri = self.issuer_uri.as_str().to_owned() + "/.well-known/openid-configuration";
        let discovery_document: OIDCDiscoveryDocument = reqwest::get(well_known_uri).await?.json().await?;
        let jwk_set : JwkSet = reqwest::get(discovery_document.jwks_uri).await?.json().await?;
        jwk_set.keys.iter().for_each(|key| {
            let decoding_key = match &key.algorithm {
                AlgorithmParameters::RSA(rsa) => Some(DecodingKey::from_rsa_components(&rsa.n, &rsa.e)),
                _ => None,
            };
            match decoding_key {
                Some(Ok(decoding_key)) => {
                    let key = key.clone();
                    self.keys.insert(key.common.key_id.clone().unwrap_or("".to_string()), decoding_key);
                },
                _ => (),

            }
        });
        Ok(())
    }
}

impl<S> FromRequestParts<S> for Claims
    where
    // keep `S` generic but require that it can produce a `OIDCState`
    // this means users will have to implement `FromRef<UsersCustomFancyState> for OIDCState`
        Arc<OIDCState>: FromRef<S>,
        S: Send + Sync,
{
    type Rejection = AuthError;
    #[instrument (name = "extracting claims", skip(parts, state))]
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = Arc::from_ref(state);
        match state.jwks_repository.write().await.fetch_keys().await {
            Err(e) => error!("{}", e.msg),
            Ok(_) => ()
        }
        let TypedHeader(Authorization(bearer)) = match parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await {
            Ok(header) => header,
            Err(e) => {
                warn!("Missing Authorization header: {}", e);
                return Err(AuthError::MissingCredentials)
            }
        };
        let repo = state.jwks_repository.read().await;
        let header = match  decode_header(bearer.token()) {
            Ok(header) => header,
            Err(e) => {
                warn!("Error decoding header: {}", e);
                return Err(AuthError::InvalidToken)
            }
        };
        let mut validation = Validation::new(header.alg);
        validation.validate_aud = false; //In our case we don't need to validate the audience

        let kid = header.kid.ok_or(AuthError::PublicKeyError)?;
        let key = match repo.get_key(kid.clone()) {
            Some(key) => key,
            None =>
                {
                    warn!("Could not find key with kid: {}", kid);
                    return Err(AuthError::PublicKeyError)
                }
        };

        let token_data = match decode::<Claims>(bearer.token(), &key, &validation) {
            Ok(token_data) => {token_data}
            Err(error) => {
                warn!("Error validating token: {}", error);
                return Err(AuthError::InvalidToken)
            }
        };
        //println!("Decoding finished");
        Ok(token_data.claims)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::PublicKeyError => (StatusCode::INTERNAL_SERVER_ERROR, "Could not fetch public keys")
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

pub struct OIDCState {
    jwks_repository: RwLock<JwksRepository>,
}

impl OIDCState {
    pub fn new(issuer: &str) -> Self {
        OIDCState { jwks_repository: RwLock::new(JwksRepository::new(issuer)) }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub scope: String,
    #[serde(default)]
    pub realm_access: RealmAccess,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

impl Default for RealmAccess {
    fn default() -> Self {
        RealmAccess { roles: vec![] }
    }
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
    PublicKeyError,
}

#[derive(Debug, Clone, Error)]
pub struct OIDCError {
    pub msg: String,
}

impl fmt::Display for OIDCError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl From<reqwest::Error> for OIDCError {
    fn from(err: reqwest::Error) -> Self {
        OIDCError { msg: err.to_string() }
    }
}

impl From<jwt::errors::Error> for AuthError {
    fn from(_err: jwt::errors::Error) -> Self {
        AuthError::InvalidToken
    }
}

impl From<serde_json::Error> for OIDCError {
    fn from(err: serde_json::Error) -> Self {
        OIDCError { msg: err.to_string() }
    }
}

impl OIDCError {
    pub fn new(msg: String) -> Self {
        OIDCError { msg }
    }
}


