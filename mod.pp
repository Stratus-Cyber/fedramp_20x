mod "fedramp_20x" {
  title       = "FedRAMP 20x Compliance"
  description = "FedRAMP 20x Key Security Indicators (KSI) compliance benchmarks and controls for AWS and Azure."

  require {
    plugin "aws" {
      min_version = "0.100.0"
    }
    plugin "azure" {
      min_version = "0.50.0"
    }
    plugin "azuread" {
      min_version = "0.10.0"
    }
  }
}
