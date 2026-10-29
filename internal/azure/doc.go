// Package azure holds the Azure SDK plumbing shared by the packages that call
// Azure: client options, concise error text and the SDK log bridge. It
// knows nothing about any particular Azure service or about building
// credentials. It imports azcore, and azidentity only to read the error that
// any credential returns when an Entra token request fails. Key Vault
// concepts such as vault URLs live in package keyvault.
package azure
