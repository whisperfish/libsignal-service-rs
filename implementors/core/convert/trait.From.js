(function() {var implementors = {};
implementors["libsignal_service"] = [{"text":"impl From&lt;DataMessage&gt; for ContentBody","synthetic":false,"types":[]},{"text":"impl From&lt;SyncMessage&gt; for ContentBody","synthetic":false,"types":[]},{"text":"impl From&lt;CallMessage&gt; for ContentBody","synthetic":false,"types":[]},{"text":"impl From&lt;ReceiptMessage&gt; for ContentBody","synthetic":false,"types":[]},{"text":"impl From&lt;TypingMessage&gt; for ContentBody","synthetic":false,"types":[]},{"text":"impl From&lt;Parse&gt; for EnvelopeParseError","synthetic":false,"types":[]},{"text":"impl From&lt;Error&gt; for EnvelopeParseError","synthetic":false,"types":[]},{"text":"impl From&lt;SessionSignedPreKey&gt; for SignedPreKey","synthetic":false,"types":[]},{"text":"impl From&lt;Type&gt; for i32","synthetic":false,"types":[]},{"text":"impl From&lt;ProvisioningVersion&gt; for i32","synthetic":false,"types":[]},{"text":"impl From&lt;Flags&gt; for i32","synthetic":false,"types":[]},{"text":"impl From&lt;Type&gt; for i32","synthetic":false,"types":[]},{"text":"impl From&lt;Type&gt; for i32","synthetic":false,"types":[]},{"text":"impl From&lt;Type&gt; for i32","synthetic":false,"types":[]},{"text":"impl From&lt;Type&gt; for i32","synthetic":false,"types":[]},{"text":"impl From&lt;Flags&gt; for i32","synthetic":false,"types":[]},{"text":"impl From&lt;Type&gt; for i32","synthetic":false,"types":[]},{"text":"impl From&lt;DecodeError&gt; for ProvisioningError","synthetic":false,"types":[]},{"text":"impl From&lt;ServiceError&gt; for ProvisioningError","synthetic":false,"types":[]},{"text":"impl From&lt;Error&gt; for ProvisioningError","synthetic":false,"types":[]},{"text":"impl From&lt;DecodeError&gt; for ServiceError","synthetic":false,"types":[]},{"text":"impl From&lt;Error&gt; for ServiceError","synthetic":false,"types":[]},{"text":"impl From&lt;SealedSessionError&gt; for ServiceError","synthetic":false,"types":[]},{"text":"impl From&lt;ServiceError&gt; for MessageReceiverError","synthetic":false,"types":[]},{"text":"impl From&lt;EnvelopeParseError&gt; for MessageReceiverError","synthetic":false,"types":[]},{"text":"impl From&lt;MacError&gt; for SealedSessionError","synthetic":false,"types":[]},{"text":"impl From&lt;DecodeError&gt; for SealedSessionError","synthetic":false,"types":[]},{"text":"impl From&lt;EncodeError&gt; for SealedSessionError","synthetic":false,"types":[]},{"text":"impl From&lt;Error&gt; for SealedSessionError","synthetic":false,"types":[]},{"text":"impl From&lt;Parse&gt; for SealedSessionError","synthetic":false,"types":[]},{"text":"impl From&lt;Error&gt; for SealedSessionError","synthetic":false,"types":[]},{"text":"impl From&lt;ServiceError&gt; for AttachmentUploadError","synthetic":false,"types":[]},{"text":"impl From&lt;Error&gt; for AttachmentUploadError","synthetic":false,"types":[]},{"text":"impl From&lt;ServiceError&gt; for MessageSenderError","synthetic":false,"types":[]},{"text":"impl From&lt;Error&gt; for MessageSenderError","synthetic":false,"types":[]},{"text":"impl From&lt;AttachmentUploadError&gt; for MessageSenderError","synthetic":false,"types":[]},{"text":"impl From&lt;Parse&gt; for ParseServiceAddressError","synthetic":false,"types":[]},{"text":"impl From&lt;Error&gt; for ParseServiceAddressError","synthetic":false,"types":[]}];
implementors["libsignal_service_actix"] = [{"text":"impl From&lt;WsClientError&gt; for AwcWebSocketError","synthetic":false,"types":[]},{"text":"impl From&lt;AwcWebSocketError&gt; for ServiceError","synthetic":false,"types":[]},{"text":"impl From&lt;ProtocolError&gt; for AwcWebSocketError","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()