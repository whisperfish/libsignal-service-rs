(function() {var implementors = {};
implementors["libsignal_service"] = [{"text":"impl&lt;Service&gt; UnwindSafe for AccountManager&lt;Service&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Service: UnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ServiceAddress","synthetic":true,"types":[]},{"text":"impl UnwindSafe for AttachmentCipherError","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for ServiceCipher","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ServiceConfiguration","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Credentials","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SignalServers","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Reaction","synthetic":true,"types":[]},{"text":"impl UnwindSafe for AttachmentPointer","synthetic":true,"types":[]},{"text":"impl UnwindSafe for CallMessage","synthetic":true,"types":[]},{"text":"impl UnwindSafe for DataMessage","synthetic":true,"types":[]},{"text":"impl UnwindSafe for GroupContext","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ReceiptMessage","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SyncMessage","synthetic":true,"types":[]},{"text":"impl UnwindSafe for TypingMessage","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Metadata","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Content","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Flags","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Flags","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Type","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ContentBody","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Sent","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Contacts","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Groups","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Blocked","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Request","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Read","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Configuration","synthetic":true,"types":[]},{"text":"impl UnwindSafe for StickerPackOperation","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ViewOnceOpen","synthetic":true,"types":[]},{"text":"impl UnwindSafe for FetchLatest","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Keys","synthetic":true,"types":[]},{"text":"impl UnwindSafe for MessageRequestResponse","synthetic":true,"types":[]},{"text":"impl UnwindSafe for UnidentifiedDeliveryStatus","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Type","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Type","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Type","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Type","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Envelope","synthetic":true,"types":[]},{"text":"impl UnwindSafe for EnvelopeEntity","synthetic":true,"types":[]},{"text":"impl UnwindSafe for WebSocketMessage","synthetic":true,"types":[]},{"text":"impl UnwindSafe for WebSocketRequestMessage","synthetic":true,"types":[]},{"text":"impl UnwindSafe for WebSocketResponseMessage","synthetic":true,"types":[]},{"text":"impl&lt;WS&gt; !UnwindSafe for MessagePipe&lt;WS&gt;","synthetic":true,"types":[]},{"text":"impl UnwindSafe for PanicingWebSocketService","synthetic":true,"types":[]},{"text":"impl UnwindSafe for WebSocketStreamItem","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Type","synthetic":true,"types":[]},{"text":"impl&lt;R&gt; UnwindSafe for Attachment&lt;R&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;R: UnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Group","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Message","synthetic":true,"types":[]},{"text":"impl UnwindSafe for PreKeyEntity","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SignedPreKeyEntity","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SignedPreKey","synthetic":true,"types":[]},{"text":"impl UnwindSafe for PreKeyState","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ProvisioningCipher","synthetic":true,"types":[]},{"text":"impl&lt;WS&gt; UnwindSafe for ProvisioningPipe&lt;WS&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;WS: UnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;WS as WebSocketService&gt;::Stream: UnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for ProvisioningError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ProvisioningStep","synthetic":true,"types":[]},{"text":"impl UnwindSafe for DeviceId","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ConfirmDeviceMessage","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ConfirmCodeMessage","synthetic":true,"types":[]},{"text":"impl UnwindSafe for DeviceCapabilities","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ProfileKey","synthetic":true,"types":[]},{"text":"impl UnwindSafe for PreKeyStatus","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ConfirmCodeResponse","synthetic":true,"types":[]},{"text":"impl UnwindSafe for PreKeyResponse","synthetic":true,"types":[]},{"text":"impl UnwindSafe for WhoAmIResponse","synthetic":true,"types":[]},{"text":"impl UnwindSafe for PreKeyResponseItem","synthetic":true,"types":[]},{"text":"impl UnwindSafe for MismatchedDevices","synthetic":true,"types":[]},{"text":"impl UnwindSafe for StaleDevices","synthetic":true,"types":[]},{"text":"impl UnwindSafe for CdnUploadAttributes","synthetic":true,"types":[]},{"text":"impl UnwindSafe for AttachmentV2UploadAttributes","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SmsVerificationCodeResponse","synthetic":true,"types":[]},{"text":"impl UnwindSafe for VoiceVerificationCodeResponse","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for ServiceError","synthetic":true,"types":[]},{"text":"impl&lt;Service&gt; UnwindSafe for MessageReceiver&lt;Service&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Service: UnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for MessageReceiverError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for UnidentifiedAccessPair","synthetic":true,"types":[]},{"text":"impl UnwindSafe for UnidentifiedAccess","synthetic":true,"types":[]},{"text":"impl UnwindSafe for UnidentifiedSenderMessageContent","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SenderCertificate","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ServerCertificate","synthetic":true,"types":[]},{"text":"impl UnwindSafe for CertificateValidator","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for SealedSessionError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for MacError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for OutgoingPushMessage","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; UnwindSafe for OutgoingPushMessages&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SendMessageResponse","synthetic":true,"types":[]},{"text":"impl UnwindSafe for AttachmentSpec","synthetic":true,"types":[]},{"text":"impl&lt;Service&gt; !UnwindSafe for MessageSender&lt;Service&gt;","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for AttachmentUploadError","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for MessageSenderError","synthetic":true,"types":[]}];
implementors["libsignal_service_actix"] = [{"text":"impl !UnwindSafe for AwcPushService","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for AwcWebSocket","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for AwcWebSocketError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SecondaryDeviceProvisioning","synthetic":true,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()