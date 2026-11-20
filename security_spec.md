# Security Specification — Probaho Auth Portal, Certificates & Design Interactions

## Data Invariants
1. A `UserProfile` document at `/users/{userId}` contains PII (`email`, `phone`) and can ONLY be read/updated/deleted by its verified owner (`request.auth.uid == userId`), and inspected by a verified Admin (`isAdmin()`).
2. A `CreatorProfile` document at `/creator_profiles/{creatorId}` stores ONLY non-PII public certificate metadata (`uid`, `displayName`, `photoURL`, `department`, `certificateCode`, `visibility`). It can be created/updated only by its verified owner (`request.auth.uid == creatorId`) and its `certificateCode` and `uid` are immutable once created.
3. A `LoginSession` document at `/login_sessions/{sessionId}` can only be created by the verified authenticated user for their own `uid` after their `/users/{uid}` profile exists, and is strictly restricted to verified Admin users (`inboxdocument17@gmail.com` or trusted `/admins/{uid}`).
4. `PublishedPhoto` (`/published_photos/{photoId}`) and `PublishedStory` (`/published_stories/{storyId}`) documents contain zero PII, are readable where `visibility == 'public'`, creatable by verified users (`uploadedByUid == request.auth.uid`), and deletable ONLY by verified Admins (`isAdmin()`).
5. `DesignLike` (`/design_likes/{likeId}`), `DesignComment` (`/design_comments/{commentId}`), and `DesignShare` (`/design_shares/{shareId}`) documents contain zero PII, enforce `userId == request.auth.uid` on creation by verified users, enforce deterministic composite `likeId == designId + '__' + request.auth.uid` on likes to prevent duplicate likes, allow authors or Admins to delete likes/comments, and forbid updates (`allow update: if false`).
6. `CommentNotification` (`/comment_notifications/{notificationId}`) documents contain zero email PII, enforce `senderUid == request.auth.uid` and `isRead == false` on creation, restrict `list` queries exclusively to `resource.data.recipientUid == request.auth.uid`, allow the recipient (`isOwner(existing().recipientUid)`) to update ONLY `['isRead', 'updatedAt']`, and allow recipient or Admin deletion.
7. All `createdAt`, `updatedAt`, and `lastLoginAt` timestamps must equal `request.time`.

## Red Team Audit Checks
- **PII Blanket Isolation**: Public QR portfolio pages read `/creator_profiles/{creatorId}` and never read `/users/{userId}` (which remains locked to `isOwner(userId) || isAdmin()`). Recipient Gmail addresses for comment notifications are kept strictly server-side via Firebase ID Token verification (`accounts:lookup`) and are never stored in shared Firestore collections or exposed via API GET routes.
- **Duplicate Like Prevention**: `likeId` is enforced to equal `incoming().designId + '__' + request.auth.uid`, blocking a user from inflating likes with arbitrary IDs.
- **Impersonation Guard**: All writes to `/creator_profiles`, `/published_photos`, `/published_stories`, `/design_likes`, `/design_comments`, `/design_shares`, and `/comment_notifications` strictly enforce `request.auth.uid` ownership and `email_verified == true`.
- **Non-Admin Delete Attempt**: Regular users cannot delete `/published_photos`, `/published_stories`, `/design_shares`, `/creator_profiles`, or other users' likes/comments/notifications.
- **Shadow Update / Resource Poisoning**: Enforced via `isValidId()`, `.size()` bounds on all strings/arrays, and `hasAll`/`hasOnly` allowlists.
- **Query Cost Guard**: `allow list` rules avoid `get()`/`exists()` calls and explicitly check `resource.data.visibility == 'public'` or `resource.data.recipientUid == request.auth.uid`.
