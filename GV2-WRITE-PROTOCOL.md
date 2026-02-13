# GV2 Write Protocol Research

Research documenting Signal Groups V2 (GV2) write protocol for create group,
add member, and remove member operations. Cross-referenced from signal-cli (Java),
Signal-Desktop (TypeScript), Signal-Android (Kotlin), and libsignal (Rust).

## Key Derivation Chain

```
32 random bytes (SecureRandom / OsRng)
  |
  v
GroupMasterKey { bytes: [u8; 32] }     -- root secret, shared to members via encrypted 1:1 message
  |
  | Sho("Signal_ZKGroup_20200424_GroupMasterKey_GroupSecretParams_DeriveFromMasterKey")
  |
  v
GroupSecretParams                      -- deterministic derivation, never leaves device
  |-- squeeze -> group_id: [u8; 32]         (public group identifier = GroupIdentifier)
  |-- squeeze -> blob_key: [u8; 32]         (AES-256-GCM-SIV key for title/desc/timer/avatar)
  |-- derive  -> uid_enc_key_pair            (Ristretto scalars a1,a2 + PublicKey A)
  |-- derive  -> profile_key_enc_key_pair    (Ristretto scalars a1,a2 + PublicKey A)
  |
  v
GroupPublicParams                      -- sent to server in Group.publicKey
  |-- group_id
  |-- uid_enc_public_key                (RistrettoPoint A = a1*G_a1 + a2*G_a2)
  |-- profile_key_enc_public_key        (RistrettoPoint A)
```

Reverse derivation: `GroupSecretParams::deriveFromMasterKey(masterKey)` is deterministic --
the same master key always produces the same secret params.

## HTTP Endpoints

All endpoints on the **storage service** host (not chat service). Auth is HTTP Basic:

```
Authorization: Basic base64("{hex(GroupPublicParams)}:{hex(AuthCredentialPresentation)}")
```

| Operation | Method | Path | Request Body | Response |
|-----------|--------|------|--------------|----------|
| Create group | `PUT` | `/v2/groups/` | `proto::Group` | `GroupResponse` |
| Modify group | `PATCH` | `/v2/groups/` | `proto::GroupChange.Actions` | `GroupChangeResponse` |
| Get group | `GET` | `/v2/groups/` | - | `GroupResponse` |
| Get change log | `GET` | `/v2/groups/logs/{fromRevision}?maxSupportedChangeEpoch=N&includeFirstState=bool&includeLastState=false` | - | `GroupChanges` |
| Avatar upload form | `GET` | `/v2/groups/avatar/form` | - | `AvatarUploadAttributes` |
| Fetch auth credentials | `GET` | `/v1/certificate/auth/group?redemptionStartSeconds=N&redemptionEndSeconds=N&zkcCredential=true` | - | JSON credentials |

Error codes: 403 (not in group), 404 (not found), 409 (already exists on PUT / conflict on PATCH).

## Proto Structures

### Group (creation payload, all fields encrypted)

```protobuf
message Group {
  bytes            publicKey                 = 1;  // GroupPublicParams serialized
  bytes            title                     = 2;  // encrypted GroupAttributeBlob
  string           avatarUrl                 = 3;  // CDN key string
  bytes            disappearingMessagesTimer = 4;  // encrypted GroupAttributeBlob
  AccessControl    accessControl             = 5;
  uint32           version                   = 6;  // revision number (0 for create)
  repeated Member  members                   = 7;
  repeated MemberPendingProfileKey membersPendingProfileKey = 8;
  repeated MemberPendingAdminApproval membersPendingAdminApproval = 9;
  bytes            inviteLinkPassword        = 10;
  bytes            description               = 11; // encrypted GroupAttributeBlob
  bool             announcements_only        = 12;
  repeated MemberBanned members_banned       = 13;
}
```

### Member

```protobuf
message Member {
  enum Role { UNKNOWN = 0; DEFAULT = 1; ADMINISTRATOR = 2; }
  bytes  userId          = 1;  // UuidCiphertext (encrypted ACI)
  Role   role            = 2;
  bytes  profileKey      = 3;  // ProfileKeyCiphertext
  bytes  presentation    = 4;  // ProfileKeyCredentialPresentation (ZK proof)
  uint32 joinedAtVersion = 5;
}
```

When `presentation` (field 4) is set, the server extracts `userId` and `profileKey` from it.
The client leaves fields 1 and 3 empty when using a presentation.

### GroupChange (server-signed envelope)

```protobuf
message GroupChange {
  bytes  actions         = 1;  // serialized GroupChange.Actions
  bytes  serverSignature = 2;  // NotarySignature from server
  uint32 changeEpoch     = 3;
}
```

### GroupChange.Actions (mutation payload)

```protobuf
message Actions {
  bytes  sourceUserId = 1;  // set by server (encrypted ACI of change author)
  uint32 version      = 2;  // MUST be currentRevision + 1
  bytes  group_id     = 25; // set by server (400 if client sets it)

  repeated AddMemberAction                   addMembers                          = 3;
  repeated DeleteMemberAction                deleteMembers                       = 4;
  repeated ModifyMemberRoleAction            modifyMemberRoles                   = 5;
  repeated ModifyMemberProfileKeyAction      modifyMemberProfileKeys             = 6;
  repeated AddMemberPendingProfileKeyAction  addMembersPendingProfileKey         = 7;
  repeated DeleteMemberPendingProfileKeyAction deleteMembersPendingProfileKey    = 8;
  repeated PromoteMemberPendingProfileKeyAction promoteMembersPendingProfileKey  = 9;
  ModifyTitleAction                          modifyTitle                         = 10;
  ModifyAvatarAction                         modifyAvatar                        = 11;
  ModifyDisappearingMessageTimerAction       modifyDisappearingMessageTimer      = 12;
  ModifyAttributesAccessControlAction        modifyAttributesAccess              = 13;
  ModifyMembersAccessControlAction           modifyMemberAccess                  = 14;
  ModifyAddFromInviteLinkAccessControlAction modifyAddFromInviteLinkAccess       = 15;
  repeated AddMemberPendingAdminApprovalAction addMembersPendingAdminApproval    = 16;
  repeated DeleteMemberPendingAdminApprovalAction deleteMembersPendingAdminApproval = 17;
  repeated PromoteMemberPendingAdminApprovalAction promoteMembersPendingAdminApproval = 18;
  ModifyInviteLinkPasswordAction             modifyInviteLinkPassword            = 19;
  ModifyDescriptionAction                    modifyDescription                   = 20;
  ModifyAnnouncementsOnlyAction              modify_announcements_only           = 21;
  repeated AddMemberBannedAction             add_members_banned                  = 22;
  repeated DeleteMemberBannedAction          delete_members_banned               = 23;
  repeated PromoteMemberPendingPniAciProfileKeyAction promote_pending_pni_aci    = 24;
  repeated ModifyMemberLabelAction           modifyMemberLabels                  = 26;
}
```

Key nested action messages:
```protobuf
message AddMemberAction           { Member added = 1; bool joinFromInviteLink = 2; }
message DeleteMemberAction        { bytes deletedUserId = 1; }  // UuidCiphertext
message AddMemberPendingProfileKeyAction { MemberPendingProfileKey added = 1; }
message AddMemberBannedAction     { MemberBanned added = 1; }
message DeleteMemberBannedAction  { bytes deletedUserId = 1; }
```

### GroupAttributeBlob (plaintext before encryption)

```protobuf
message GroupAttributeBlob {
  oneof content {
    string title                        = 1;
    bytes  avatar                       = 2;
    uint32 disappearingMessagesDuration = 3;
    string descriptionText              = 4;
  }
}
```

### GroupContextV2 (client-to-client distribution in DataMessage)

```protobuf
message GroupContextV2 {
  optional bytes  masterKey    = 1;  // raw 32-byte GroupMasterKey
  optional uint32 revision     = 2;  // revision after change
  optional bytes  groupChange  = 3;  // serialized GroupChange (server-signed)
}
```

### Response types

```protobuf
message GroupResponse {
  Group group = 1;
  bytes group_send_endorsements_response = 2;
}

message GroupChangeResponse {
  GroupChange group_change = 1;
  bytes group_send_endorsements_response = 2;
}
```

## Encryption Operations

All encryption uses `ClientZkGroupCipher` initialized with `GroupSecretParams`:

| Plaintext | Method | Output | Deterministic? |
|-----------|--------|--------|---------------|
| ServiceId (ACI/PNI) | `clientZkGroupCipher.encrypt(serviceId)` | `UuidCiphertext` | Yes |
| ProfileKey + ACI | `clientZkProfileOps.createProfileKeyCredentialPresentation(random, groupSecretParams, credential)` | `ProfileKeyCredentialPresentation` | No |
| Title string | `clientZkGroupCipher.encryptBlob(GroupAttributeBlob{title}.encode())` | Encrypted blob | No (random nonce) |
| Description | `clientZkGroupCipher.encryptBlob(GroupAttributeBlob{descriptionText}.encode())` | Encrypted blob | No |
| Timer | `clientZkGroupCipher.encryptBlob(GroupAttributeBlob{disappearingMessagesDuration}.encode())` | Encrypted blob | No |
| Avatar | `clientZkGroupCipher.encryptBlob(GroupAttributeBlob{avatar}.encode())` | Encrypted blob (uploaded to CDN) | No |

### UID Encryption (Ristretto)

```
M1 = SHO("Signal_ZKGroup_20200424_UID_CalcM1", service_id_bytes).get_point()
M2 = lizard_encode(uuid_bytes)  // reversible Ristretto encoding via SHA-256
E_A1 = a1 * M1
E_A2 = a2 * E_A1 + M2
UuidCiphertext = (E_A1, E_A2)
```

Decryption: `M2 = E_A2 - a2 * E_A1`, then lizard_decode to get UUID bytes.

### Blob Encryption (AES-256-GCM-SIV)

```
nonce = random 12 bytes (via SHO)
ciphertext = AES-256-GCM-SIV(blob_key, nonce, plaintext)
wire_format = [ciphertext | nonce | 1 reserved byte]
```

## 1. CREATE GROUP -- Full Flow

### Step 1: Generate GroupSecretParams
```
GroupSecretParams groupSecretParams = GroupSecretParams.generate();
// Internally: 32 random bytes -> native GroupSecretParams_GenerateDeterministic()
```

### Step 2: Derive GroupId
```
GroupIdentifier groupId = groupSecretParams.getPublicParams().getGroupIdentifier();
// 32 bytes, used as the group's public identifier
```

### Step 3: Gather credentials for self
```
ExpiringProfileKeyCredential selfCredential = getProfileKeyCredential(selfAci);
// Obtained from server via profile key credential request (ZK operation)
```

### Step 4: Gather credentials for all members
```
For each member:
  GroupCandidate { serviceId, Optional<ExpiringProfileKeyCredential> }
// If no credential available, member becomes MemberPendingProfileKey (invite)
```

### Step 5: Build encrypted Group proto

```
Group.Builder group = Group.Builder()
    .version(0)
    .publicKey(groupSecretParams.getPublicParams().serialize())
    .title(encryptBlob(GroupAttributeBlob{title}))
    .disappearingMessagesTimer(encryptBlob(GroupAttributeBlob{timer}))
    .accessControl(AccessControl{attributes: MEMBER, members: MEMBER});
```

### Step 6: Encrypt self as ADMINISTRATOR
```
ProfileKeyCredentialPresentation presentation =
    clientZkProfileOps.createProfileKeyCredentialPresentation(
        random, groupSecretParams, selfCredential);
Member { role: ADMINISTRATOR, presentation: presentation.serialize() }
```

### Step 7: Encrypt each member
```
If has ExpiringProfileKeyCredential:
    Member { role: DEFAULT, presentation: presentation.serialize() }
    -> added to group.members

If no credential (invited as pending):
    UuidCiphertext ct = clientZkGroupCipher.encrypt(serviceId)
    Member { role: DEFAULT, userId: ct.serialize() }
    MemberPendingProfileKey { member: above, addedByUserId: encrypt(selfAci) }
    -> added to group.membersPendingProfileKey
```

### Step 8: Optional avatar upload
```
String cdnKey = uploadAvatar(encryptBlob(GroupAttributeBlob{avatar}), groupSecretParams, auth);
group.avatarUrl(cdnKey);
```

### Step 9: PUT to server
```
GroupsV2AuthorizationString auth = getGroupAuthForToday(groupSecretParams);
HTTP PUT /v2/groups/ with body = Group.encode()
Response: GroupResponse { group, group_send_endorsements_response }
```

### Step 10: Distribute to members
```
GroupContextV2 {
    masterKey:   [32-byte raw GroupMasterKey]
    revision:    0
    groupChange: null  // no change for creation
}
// Sent as DataMessage to all members (including pending) except self
```

## 2. ADD MEMBER -- Full Flow

### Step 1: Get GroupOperations for this group
```
GroupSecretParams params = GroupSecretParams.deriveFromMasterKey(masterKey);
```

### Step 2: Gather credentials for new members
```
GroupCandidate { serviceId, Optional<ExpiringProfileKeyCredential> }
```

### Step 3: Check banned list (auto-unban if adding banned member)
```
If member is currently banned:
    Add DeleteMemberBannedAction { deletedUserId: encrypt(serviceId) }
```

### Step 4: Build GroupChange.Actions
```
For each candidate with credential:
    ProfileKeyCredentialPresentation presentation = ...create presentation...
    AddMemberAction { added: Member { role: DEFAULT, presentation } }

For each candidate without credential:
    UuidCiphertext ct = clientZkGroupCipher.encrypt(serviceId)
    AddMemberPendingProfileKeyAction {
        added: MemberPendingProfileKey {
            member: Member { role: DEFAULT, userId: ct },
            addedByUserId: encrypt(selfAci)
        }
    }

actions.version = currentRevision + 1
```

### Step 5: Local validation
```
// Decrypt change locally and apply to local state to verify correctness
DecryptedGroupChange decrypted = groupOps.decryptChange(actions, selfAci);
DecryptedGroup newState = DecryptedGroupUtil.apply(previousState, decrypted);
```

### Step 6: PATCH to server
```
HTTP PATCH /v2/groups/ with body = GroupChange.Actions.encode()
Response: GroupChangeResponse { group_change (server-signed), group_send_endorsements_response }
```

### Step 7: Distribute to all members (old + new)
```
GroupContextV2 {
    masterKey:   [32-byte GroupMasterKey]
    revision:    N+1
    groupChange: [serialized GroupChange with server signature]
}
// Sent to union of members before AND after the change
```

## 3. REMOVE MEMBER -- Full Flow

### Step 1: Build GroupChange.Actions
```
For each member to remove:
    DeleteMemberAction { deletedUserId: clientZkGroupCipher.encrypt(aci).serialize() }

actions.version = currentRevision + 1
```

### Step 2: Optional ban (if also banning)
```
If banning:
    AddMemberBannedAction { added: MemberBanned { userId: encrypt(serviceId) } }
    // If ban list full, evict oldest: DeleteMemberBannedAction for oldest entries
```

### Step 3: PATCH to server
```
HTTP PATCH /v2/groups/ with body = GroupChange.Actions.encode()
Response: GroupChangeResponse { group_change, group_send_endorsements_response }
```

### Step 4: Distribute to all members (including removed member)
```
Recipients = union of members before AND after the change
// Removed member receives notification that they were removed
GroupContextV2 {
    masterKey:   [32-byte GroupMasterKey]
    revision:    N+1
    groupChange: [serialized GroupChange with server signature]
}
```

## Auth Credential Lifecycle

```
1. Client fetches AuthCredentialWithPniResponse from server
   GET /v1/certificate/auth/group?redemptionStartSeconds=...&redemptionEndSeconds=...
   Server returns 7 days of credentials

2. Client verifies and extracts credential:
   AuthCredentialWithPni = clientZkAuthOps.receiveAuthCredentialWithPniAsServiceId(
       aci, pni, redemptionTime, response)

3. Client creates presentation scoped to specific group:
   AuthCredentialPresentation = clientZkAuthOps.createAuthCredentialPresentation(
       random, groupSecretParams, authCredential)

4. Build auth header:
   username = hex(GroupPublicParams.serialize())
   password = hex(AuthCredentialPresentation.serialize())
   Authorization: Basic base64("{username}:{password}")
```

## GroupSendEndorsement

Returned in GroupResponse and GroupChangeResponse. Authorizes sending messages to
group members via sealed sender without per-message auth.

```
1. Server issues GroupSendEndorsementsResponse for ALL members at once
2. Client decomposes into per-member GroupSendEndorsement tokens
3. Client combines endorsements for target recipients
4. Client converts to bearer token for send requests
```

Default expiration: end of next day (minimum 25 hours validity).

## Conflict Resolution

On 409 (conflict): fetch latest group state, compare with intended change,
strip already-applied actions, rebuild against new revision. Up to 5 retries.

On 400 (bad request): clear and re-fetch profile key credentials, retry once.

## Current State of Rust Ecosystem

### whisperfish/libsignal-service-rs (upstream)

**Has (read/decrypt only):**
- `GroupsManager::fetch_encrypted_group()` -- GET /v1/groups/
- `GroupsManager::retrieve_avatar()`
- `GroupsManager::decrypt_group_context()`
- `GroupOperations::decrypt_group()` -- all decrypt methods
- `GroupOperations::decrypt_group_change()`
- Full proto definitions for all wire types
- Full model types (Group, Member, GroupChange enum, etc.)

**Missing (write/encrypt -- LEG 2 deliverable):**
- Encryption: `encrypt_service_id()`, `encrypt_profile_key()`, `encrypt_blob()`,
  `encrypt_title()`, `encrypt_description()`, `encrypt_timer()`
- Action builders: `build_add_member_action()`, `build_remove_member_action()`,
  `build_modify_title_action()`, etc.
- HTTP methods: `PUT /v2/groups/` (create), `PATCH /v2/groups/` (modify)
- High-level: `GroupsManager::create_group()`, `GroupsManager::modify_group()`

## Implementation Notes for Rust Port

1. **GroupMasterKey is the only thing stored/shared.** Everything else is deterministically
   derived. 32 bytes.

2. **ProfileKeyCredentialPresentation is the ZK proof for adding full members.** When
   adding a member with an ExpiringProfileKeyCredential, create a presentation that proves
   knowledge of the profile key. Server extracts userId and profileKey from it.

3. **Pending members use encrypted userId directly.** Without a profile key credential,
   encrypt their ServiceId into UuidCiphertext and set it on Member.userId.

4. **Revision increment is mandatory.** Every GroupChange.Actions must have
   version = previousState.revision + 1. Server rejects wrong versions.

5. **Local validation before server call.** Decrypt change locally and apply to local
   state to verify correctness before sending to server.

6. **Distribution includes server-signed GroupChange.** After PATCH, the server returns
   a signed GroupChange. This signed change is distributed in GroupContextV2.groupChange.

7. **Member collection for distribution.** For updates (add/remove), recipients are the
   union of members before AND after the change (removed members still receive removal).

8. **Auto-unban on add.** When adding a member who is banned, include
   DeleteMemberBannedAction in the same change.

9. **Auth credential is time-scoped.** AuthCredentialWithPni fetched for 7-day window.
   Presentation is scoped to specific group via GroupSecretParams.

10. **encryptBlob handles padding.** The native implementation adds random padding before
    encryption. During decryption, minimum 29 bytes validated, padding stripped.

11. **sourceUserId and group_id are server-set.** Do NOT set fields 1 and 25 on
    GroupChange.Actions -- the server fills these. Setting group_id returns 400.

## Reference Implementations

| Source | Language | Key Files |
|--------|----------|-----------|
| signal-cli | Java | `helper/GroupV2Helper.java`, `helper/GroupHelper.java` |
| Signal-Desktop | TypeScript | `ts/groups.ts` (createGroupV2, modifyGroupV2), `ts/textsecure/WebAPI.ts` |
| Signal-Android | Kotlin/Java | `GroupManagerV2.java`, `GroupsV2Operations.java`, `GroupsV2Api.java`, `PushServiceSocket.java` |
| libsignal | Rust | `rust/zkgroup/src/api/groups/group_params.rs`, `group_send_endorsement.rs` |
| Academic | Paper | "The Signal Private Group System" (Chase, Perrin, Zaverucha, 2019) |
