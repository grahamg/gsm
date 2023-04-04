# Git/Go/Graham Secret Management (GSM)

## What is GSM, and why is use something like this useful?
Simply put this is a secret management utility that acts as a wrapper around Git and OpenSSL.

Instead of relying on a paid externally hosted API as a service, this project allows the user
to host their own secrets managent service on a local workstation to a server controlled by the
end user.

Key value pairs are stored as encrypted cipher text in a Git repository where any modification
of the secrets being managed are version controlled and can be rolled back, tagged or forked at
the user's complete control.

## How does this work, how are encrypted values stored and managed?
JSON values are encrypted in a Git repository and then exported to a single file.

The JSON data is saved in a file named secrets.txt and then encrypted with `openssl`
as follows: `openssl enc -aes-256-cbc -salt -in data.json -out data.json.enc -k mypassword`

Any time a key name, value or tag is modified the state is comitted to the repository with an
automatically derived commit message.

The Git repository is saved to a single file using the `git bundle --all` command.
The `--all` flag tells Git to include all branches and tags in the bundle.

## So my secrets are stored on someone elses's infrastructure?
This utility can be run locally on your own workstation or hosted as a service on a server that your able
to administer.

If you choose to use this locally, a command line client is available. However, the same actions can be used
as an api if you choose to configure it as a service to bind to an external port on a public IP address.

It's whatever you choose; your in control. Nobody is hosting this service as a means to derive a profit.

## What method of encryption is used by this utility service?
As of 2023, the strongest and most robust encryption algorithm supported by OpenSSL is the Advanced Encryption Standard (AES) with a key size of 256 bits. This algorithm is widely used in secure communications and is considered secure against known attacks.

AES is a symmetric key encryption algorithm, which means that the same secret key is used for both encryption and decryption. It is highly efficient and can encrypt and decrypt data quickly, making it suitable for use in a wide range of applications.

## What actions/feature set is supported by this utility service?
Actions
0. Open an existing (saved) safe that has already been exported to a file.
1. Create a new safe (initially in memory only).
2. Export the currently open safe buffer to a file as an encrypted payload.
3. Show the hash value for a given safe (by name).
4. Add a new entry in the currently open safe buffer.
5. Modify an existing entry in the currently open safe buffer.
6. Archive an active entry in the currently open safe buffer.
7. Unarchive an archived entry in the currently open safe buffer.
8. Add a new tag to an active entry in the currently open safe buffer.
9. Remove an active tag from an active entry in the currently open safe buffer.

## How does a user interact with this utility service?
Actions  => Corresponding API Calls

0. HTTP GET /api/v1/safe/open?as=`uniqueSafeBufferName`

1. HTTP POST /api/v1/safe/create?as=`uniqueSafeBufferName`

2. HTTP GET /api/v1/safe/export?as=`uniqueSafeBufferName`

3. HTTP GET /api/v1/safe/hash?as=`uniqueSafeBufferName`

4. HTTP PUT /api/v1/safe/entry?key=`uniqueKeyNameIdentifier`

5. HTTP PATCH /api/v1/safe/entry?key=`uniqueKeyNameIdentifier`

6. HTTP PATCH /api/v1/safe/archive?key=`uniqueKeyNameIdentifier`

7. HTTP PATCH /api/v1/safe/unarchive?key=`uniqueKeyNameIdentifier`

8. HTTP PUT /api/v1/safe/tag?key=`uniqueKeyNameIdentifier`

9. HTTP DELETE /api/v1/safe/tag?key=`uniqueKeyNameIdentifier`

10. HTTP TEAPOT / show supplimental about info.
