resource "az-confidential_secret" "confidential_secret" {
  encrypted_secret = "AiN87c9VbdKptdRII+TB9hP1EyQT3MaGvsdP1WkDtde++VLwVgY5Ah6bf8RkjuUX1MKWgkYnBMHPaYf9Rnvrk4aJjfqhPPlFesSv0s2m1sNIgPJcugRN15vIDbe94dzDKJMLPz3vmbh2/2t2+m1uB9hNt1zu3TaYrKrpNRRqYj9RJnrUXgDre3Vzq0ynEZEVPxp0gLPyDOv8W0RJ4YaOan5zoEenn3fklembtWuX2t6d0lkkyqixz0O50f/izjldNd+GnJuBH7PeuqrKcEe3XMWeHWyizfthSMZER2PCyQXUzh1YLmd9OWvS7TgGS2A9UeDGuu4ZBPW1EAKkzBiLwnRnFhPMPYwfcJh9WwRr/YS1waijRT2NlqJ5dxFvMamUIci+Y8H8WzxW19U7kzw94pDtf4xLAJR1ob9F6ZLXT3sEWdk9xl+o/uujb9jm1o89mWzXfvbBgjceQ1fuqecp13JT+ZBGDeZDJkBO+5RJVVNk91vaMcivK9PBq3rvJqZRcFQuMETi1Emv7zAaUpY/jBpgqGVzzH20uLTbiNX2iwTiO/RzOy6if5xzk5Ne3EFuhYwCsewrsxJVSoV+7GD0uCTr03aJZIQgLyLnWVBWm7SuyuG9wOYYwXecTaDZYxP6EMiMlktzZr/Fg8A2LoooWQwRlPRCvK0Q1kXaOdqx18g="

  # This secret is enabled for operation. Optionally, there is an option
  # to temporarily disable it.
  enabled = true

  # The secret version cannot be used before this date
  # Needs to be formatted yyyy-mm-ddTHH:MM:SS'Z'
  # not_before_date = "2025-06-07T18:35:05Z"

  # The secret version cannot be used after this date
  # Needs to be formatted yyyy-mm-dd'T'HH:MM:SS'Z'
  # not_after_date = "2026-06-07T18:35:05Z"

  tags = {
    # Fill the tags as desired
    # tagName =  "TagValue"
  }

  destination_secret = {
    vault_name = "lspwd2-d-confidential-kv"
    name = "secretv2"
  }
}
