use async_trait::async_trait;
use thiserror::Error;
use zolana_api::{ApiError, BlockingInsideRuntime, ZolanaApi};
use zolana_client::{
    indexer::{indexer_error, AsyncZolanaIndexer, ZolanaIndexer},
    ClientError,
};
use zolana_indexer_api::RpcMethod;
use zolana_ring_indexer::rpc::{
    method::{GetRingKeyRegistryEntry, GetRingKeyRegistryRegisterProof, GetRingSpendRecord},
    GetRingKeyRegistryEntryResponse, GetRingKeyRegistryRegisterProofResponse,
    GetRingSpendRecordResponse, RingMemberProofRequest, RingRpcError, RingSpendRecordRequest,
};

#[derive(Debug, Error)]
pub enum RingIndexerError {
    #[error(transparent)]
    Refused(#[from] RingRpcError),
    #[error(transparent)]
    Client(#[from] ClientError),
}

impl From<BlockingInsideRuntime> for RingIndexerError {
    fn from(error: BlockingInsideRuntime) -> Self {
        Self::Client(error.into())
    }
}

pub trait RingIndexer {
    fn get_ring_spend_record(
        &self,
        _request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, RingIndexerError> {
        Err(unsupported::<GetRingSpendRecord>())
    }

    fn get_ring_key_registry_entry(
        &self,
        _request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, RingIndexerError> {
        Err(unsupported::<GetRingKeyRegistryEntry>())
    }

    fn get_ring_key_registry_register_proof(
        &self,
        _request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, RingIndexerError> {
        Err(unsupported::<GetRingKeyRegistryRegisterProof>())
    }
}

#[async_trait]
pub trait AsyncRingIndexer: Send + Sync {
    async fn get_ring_spend_record(
        &self,
        _request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, RingIndexerError> {
        Err(unsupported::<GetRingSpendRecord>())
    }

    async fn get_ring_key_registry_entry(
        &self,
        _request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, RingIndexerError> {
        Err(unsupported::<GetRingKeyRegistryEntry>())
    }

    async fn get_ring_key_registry_register_proof(
        &self,
        _request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, RingIndexerError> {
        Err(unsupported::<GetRingKeyRegistryRegisterProof>())
    }
}

impl RingIndexer for ZolanaIndexer {
    fn get_ring_spend_record(
        &self,
        request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, RingIndexerError> {
        self.runtime()
            .block_on(call::<GetRingSpendRecord>(self.api(), request))
    }

    fn get_ring_key_registry_entry(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, RingIndexerError> {
        self.runtime()
            .block_on(call::<GetRingKeyRegistryEntry>(self.api(), request))
    }

    fn get_ring_key_registry_register_proof(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, RingIndexerError> {
        self.runtime()
            .block_on(call::<GetRingKeyRegistryRegisterProof>(self.api(), request))
    }
}

#[async_trait]
impl AsyncRingIndexer for AsyncZolanaIndexer {
    async fn get_ring_spend_record(
        &self,
        request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, RingIndexerError> {
        call::<GetRingSpendRecord>(self.api(), request).await
    }

    async fn get_ring_key_registry_entry(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, RingIndexerError> {
        call::<GetRingKeyRegistryEntry>(self.api(), request).await
    }

    async fn get_ring_key_registry_register_proof(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, RingIndexerError> {
        call::<GetRingKeyRegistryRegisterProof>(self.api(), request).await
    }
}

async fn call<M: RpcMethod>(
    api: &ZolanaApi,
    request: M::Request,
) -> Result<M::Response, RingIndexerError> {
    api.call::<M>(request).await.map_err(ring_error)
}

fn ring_error(error: ApiError) -> RingIndexerError {
    if let ApiError::JsonRpc {
        code: Some(code), ..
    } = &error
    {
        if let Some(refusal) = RingRpcError::from_code(*code) {
            return refusal.into();
        }
    }
    indexer_error(error).into()
}

fn unsupported<M: RpcMethod>() -> RingIndexerError {
    ClientError::UnsupportedRpcMethod(M::NAME).into()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use http::{HeaderMap, StatusCode};
    use serde_json::{json, Value};
    use solana_signature::Signature;
    use zolana_api::{
        BlockingHttpClient, BlockingZolanaApi, HttpClient, HttpFuture, HttpRequest, HttpResponse,
    };
    use zolana_indexer_api::{Hash, SerializablePubkey};

    use super::*;

    #[derive(Clone, Debug)]
    struct Canned {
        response: Value,
        sent: Arc<Mutex<Option<(String, Value)>>>,
    }

    impl Canned {
        fn new(response: Value) -> Self {
            Self {
                response,
                sent: Arc::default(),
            }
        }

        fn answer(&self, request: HttpRequest) -> Result<HttpResponse, ApiError> {
            let body = serde_json::from_slice(&request.body).unwrap();
            *self.sent.lock().unwrap() = Some((request.url.clone(), body));
            Ok(HttpResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: serde_json::to_vec(&self.response).unwrap(),
            })
        }

        fn sent(&self) -> (String, Value) {
            self.sent.lock().unwrap().clone().unwrap()
        }
    }

    impl HttpClient for Canned {
        fn send<'a>(&'a self, request: HttpRequest) -> HttpFuture<'a> {
            let answer = self.answer(request);
            Box::pin(async move { answer })
        }
    }

    impl BlockingHttpClient for Canned {
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, ApiError> {
            self.answer(request)
        }
    }

    fn rpc_result(result: Value) -> Value {
        json!({"id": "test-account", "jsonrpc": "2.0", "result": result})
    }

    fn query() -> RingSpendRecordRequest {
        RingSpendRecordRequest {
            ring_program_id: SerializablePubkey::from([1; 32]),
            member: Hash([2; 32]),
        }
    }

    #[test]
    fn spend_record_transport_returns_the_indexed_record() {
        let http = Canned::new(rpc_result(json!({
            "context": {"blockTime": 90, "slot": 20},
            "record": {
                "transaction": {
                    "slot": 18,
                    "txSignature": Signature::from([7; 64]).to_string(),
                    "eventIndex": 1,
                    "outputSlots": [],
                    "messages": [],
                    "nullifiers": [],
                    "proofless": false,
                },
                "outputIndex": 2,
            },
        })));
        let indexer = ZolanaIndexer::with_api(BlockingZolanaApi::with_client(
            "http://indexer",
            http.clone(),
        ));
        let response = indexer.get_ring_spend_record(query()).unwrap();
        let (url, body) = http.sent();
        assert_eq!(url, "http://indexer/getRingSpendRecord");
        assert_eq!(body["method"], "getRingSpendRecord");
        assert_eq!(body["params"], serde_json::to_value(query()).unwrap());
        assert_eq!(response.context.slot, 20);
        let record = response.record.unwrap();
        assert_eq!(record.output_index, 2);
        assert_eq!(record.transaction.slot, 18);
        assert_eq!(record.transaction.event_index, Some(1));
    }

    #[tokio::test]
    async fn async_spend_record_transport_reads_an_unregistered_member_as_none() {
        let http = Canned::new(rpc_result(json!({
            "context": {"blockTime": 90, "slot": 21},
            "record": null,
        })));
        let indexer =
            AsyncZolanaIndexer::with_api(ZolanaApi::with_client("http://indexer", http.clone()));
        let response = indexer.get_ring_spend_record(query()).await.unwrap();
        assert_eq!(http.sent().1["method"], "getRingSpendRecord");
        assert_eq!(response.context.slot, 21);
        assert!(response.record.is_none());
    }

    #[test]
    fn preserves_ring_error_codes() {
        for expected in RingRpcError::ALL {
            let error = ring_error(ApiError::JsonRpc {
                method: GetRingSpendRecord::NAME,
                code: Some(i64::from(expected.code())),
                message: Some("projection error".into()),
            });
            assert!(
                matches!(error, RingIndexerError::Refused(refused) if refused == expected),
                "{expected:?}"
            );
        }
        let other = ring_error(ApiError::JsonRpc {
            method: GetRingSpendRecord::NAME,
            code: Some(-32603),
            message: Some("internal".into()),
        });
        assert!(matches!(
            other,
            RingIndexerError::Client(ClientError::IndexerUnavailable(_))
        ));
    }
}
