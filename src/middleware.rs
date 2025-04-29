use jsonrpsee::{
    MethodResponse,
    core::{
        ClientError,
        middleware::{Batch, Notification, RpcServiceT},
        traits::ToRpcParams as _,
    },
    types::{ErrorCode, Id, Request},
};

use crate::{
    auth::AuthenticatedParams,
    crypto::{Keypair, PeerId},
};

pub struct Sign<S> {
    keypair: Keypair,
    inner: S,
}

impl<S> Sign<S> {
    pub fn new(keypair: Keypair, inner: S) -> Self {
        Self { keypair, inner }
    }
}

impl<S, MR, NR, BR> RpcServiceT for Sign<S>
where
    S: RpcServiceT<
            MethodResponse = Result<MR, ClientError>,
            NotificationResponse = Result<NR, ClientError>,
            BatchResponse = Result<BR, ClientError>,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = S::MethodResponse;
    type NotificationResponse = S::NotificationResponse;
    type BatchResponse = S::BatchResponse;

    fn call<'a>(
        &self,
        request: Request<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        let keypair = self.keypair.clone();

        async move {
            let Ok(auth) = AuthenticatedParams::prepare_now(
                &keypair,
                &request.id,
                request.method.as_ref(),
                request.params,
            ) else {
                return Err(ClientError::Custom(
                    "Failed to prepare authenticated params".into(),
                ));
            };

            let Ok(params) = auth.to_rpc_params() else {
                return Err(ClientError::Custom(
                    "Failed to serialize authenticated params".into(),
                ));
            };

            let request = Request::owned(request.method.into_owned(), params, request.id);

            inner.call(request).await
        }
    }

    #[expect(clippy::manual_async_fn)]
    fn batch<'a>(
        &self,
        _requests: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        async {
            Err(ClientError::Custom(
                "Authenticated batch calls are not supported".into(),
            ))
        }
    }

    #[expect(clippy::manual_async_fn)]
    fn notification<'a>(
        &self,
        _n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        async {
            Err(ClientError::Custom(
                "Authenticated notifications are not supported".into(),
            ))
        }
    }
}

pub struct Verify<S> {
    inner: S,
}

impl<S> Verify<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> RpcServiceT for Verify<S>
where
    S: RpcServiceT<MethodResponse = MethodResponse> + Send + Sync + Clone + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = MethodResponse;
    type BatchResponse = MethodResponse;

    fn call<'a>(
        &self,
        mut request: Request<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let inner = self.inner.clone();

        async move {
            let Ok(auth) = request.params().parse::<AuthenticatedParams>() else {
                return MethodResponse::error(request.id, ErrorCode::InvalidRequest);
            };

            if auth.verify_now(&request.id, request.method_name()).is_err() {
                return MethodResponse::error(request.id, ErrorCode::InvalidRequest);
            }

            request.params = auth.inner;
            request.extensions_mut().insert(PeerId::from(auth.signer));

            inner.call(request).await
        }
    }

    #[expect(clippy::manual_async_fn)]
    fn batch<'a>(
        &self,
        _requests: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        async { MethodResponse::error(Id::Null, ErrorCode::InternalError) }
    }

    #[expect(clippy::manual_async_fn)]
    fn notification<'a>(
        &self,
        _n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        async { MethodResponse::error(Id::Null, ErrorCode::InternalError) }
    }
}
