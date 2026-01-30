benchmark "fedramp_20x_azure" {
  title       = "FedRAMP 20x - Azure"
  description = "FedRAMP 20x KSI compliance for Azure"

  children = [
    control.ksi_iam_01_azure,
    control.ksi_iam_02_azure,
    control.ksi_iam_03_azure,
    control.ksi_iam_05_azure,
    control.ksi_cna_01_azure,
    control.ksi_cna_02_azure,
    control.ksi_cna_03_azure,
    control.ksi_cna_04_azure,
    control.ksi_mla_01_azure,
    control.ksi_inr_01_azure,
    control.ksi_piy_01_azure,
    control.ksi_rpl_01_azure,
    control.ksi_svc_01_azure,
    control.ksi_svc_06_azure,
  ]
}
