use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use axum::{async_trait, extract::{TypedHeader}, headers::{authorization::Bearer, Authorization}, http::{request::Parts, StatusCode}, response::{IntoResponse, Response}, Json, RequestPartsExt};
use axum::extract::{FromRef, FromRequestParts};

use jsonwebkey::{JsonWebKey};
use jsonwebtoken::{Algorithm, decode, decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use reqwest;
use serde_json::json;
use tokio::sync::RwLock;
use thiserror::Error;

extern crate jsonwebtoken as jwt;
extern crate jsonwebkey as jwk;

#[derive(Debug)]
#[derive(Deserialize)]
struct OIDCDiscoveryDocument {
    pub jwks_uri: String,
}

pub struct KeyContainer {
    decoding_key: DecodingKey,
    validation: Validation,
}


pub struct JwksRepository {
    issuer_uri: String,
    keys_fetched: bool,
    decoding_keys: HashMap<String, KeyContainer>,
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
        Self { issuer_uri: issuer.to_string(), keys_fetched: false, decoding_keys: HashMap::new() }
    }
    pub fn get_key(&self, kid: String) -> Option<&KeyContainer> {
        self.decoding_keys.get(kid.as_str())
    }

    pub async fn fetch_keys(&mut self) -> Result<(), OIDCError> {
        if self.keys_fetched {
            return Ok(());
        }
        let well_known_uri = self.issuer_uri.as_str().to_owned() + "/.well-known/openid-configuration";
        let discovery_document: OIDCDiscoveryDocument = reqwest::get(well_known_uri).await?.json().await?;
        let oidc_jkws_response: OIDCJwksResponse = reqwest::get(discovery_document.jwks_uri).await?.json().await?;

        self.decoding_keys.clear();
        oidc_jkws_response.keys.iter()
            .filter(|key| key.alg == "RS256" && key.r#use == "sig")
            .map(|key| -> Result<JsonWebKey, jwk::Error> { serde_json::to_string(key)?.parse() })
            .filter(|result| {
                if result.is_ok() {
                    true
                } else {
                    eprintln!("Could not parse key. Error: {:?}", result.as_ref().err().unwrap());
                    false
                }
            }
            )
            .map(|result| result.unwrap())
            .for_each(|key| {
                self.decoding_keys.insert(key.key_id.unwrap(),
                                          KeyContainer {
                                              decoding_key: key.key.to_decoding_key(),
                                              validation: Validation::new(Algorithm::from(key.algorithm.unwrap())),
                                          });
            });
        println!("Fetched keys {:?}", self.decoding_keys.keys());
        self.keys_fetched = true;
        Ok(())
    }
}


#[async_trait]
impl<S> FromRequestParts<S> for Claims
    where
    // keep `S` generic but require that it can produce a `OIDCState`
    // this means users will have to implement `FromRef<UsersCustomFancyState> for OIDCState`
        Arc<OIDCState>: FromRef<S>,
        S: Send + Sync,
{
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = Arc::from_ref(state);
        match state.jwks_repository.write().await.fetch_keys().await {
            Err(e) => eprintln!("{}", e.msg),
            Ok(_) => ()
        }
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        let repo = state.jwks_repository.read().await;
        let _header = decode_header(bearer.token())?.kid.ok_or(AuthError::PublicKeyError)?;
        //println!("Decoded header {}", header);
        let key_container = repo.get_key(decode_header(bearer.token())?.kid.ok_or(AuthError::PublicKeyError)?).ok_or(AuthError::PublicKeyError)?;
        let token_data = decode::<Claims>(bearer.token(), &key_container.decoding_key, &key_container.validation)
            .map_err(|_| AuthError::InvalidToken)?;
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
    pub given_name: String,
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


