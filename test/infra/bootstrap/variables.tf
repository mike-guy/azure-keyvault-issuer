variable "subscription_id" {
  description = "The subscription dedicated to e2e testing."
  type        = string
}

variable "location" {
  description = "The Azure region of everything bootstrap makes."
  type        = string
  default     = "uksouth"
}

variable "github_owner" {
  description = "The GitHub user or organisation that owns the repository."
  type        = string
  default     = "mike-guy"
}

variable "github_owner_id" {
  description = "The numeric ID of the GitHub owner, which the immutable subject claim includes."
  type        = string
  default     = "48997783"
}

variable "github_repository_id" {
  description = "The numeric ID of the GitHub repository, which the immutable subject claim includes."
  type        = string
  default     = "1433360854"
}

variable "github_repository" {
  description = "The GitHub repository whose workflows sign in to Azure."
  type        = string
  default     = "azure-keyvault-issuer"
}

variable "github_environments" {
  description = "The GitHub environments whose jobs may sign in. An environment can require approval, which a pull request from a fork cannot get round."
  type        = set(string)
  default     = ["e2e"]
}
