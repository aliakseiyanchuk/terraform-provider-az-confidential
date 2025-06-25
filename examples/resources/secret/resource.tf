# Copyright (c) HashiCorp, Inc.

resource "az-confidential_secret" "conf_secret" {
  content = "H4sIAAAAAAAA/1TSu7aqOACA4Z6nmN41CxDQbTEFKHcIgmAMHReRSAAlhNvTzzq7O3/519+/f9J00wb/nAMQ6yD+PRxK0MGCxf27k/yszoD/0PdavcQrtp9JqQIkjgiRLVXCQQ9lgKPhVd4z5QOt5cxkdOXghJODddCVMFfpNfInL6+DNAi+9zXoXtcz7g0I6u8kEdtHLIzEgI959eRvu7v1UrWMS1+dUWioIP5mPMEp1BIloWokNDbOppnmXqA0kkMiPJYgv3z1Opy2VZgPh9hOC6YpHGVD1t9u9JPZ7cta3c9UTRJoPSoNoLzYeaGWx9e8Y2ewf7RbJGu74dI6wofwIPArx+EcorcNMGXn7CZW8/O2F2yLYw+lOT91WyzGDQVuuCxf/9kH2Kxvo830Ow2/OHuW8ca48QhVd14V9yhfk/0i5LOq85epZy39ilUgS2GwMAMuO3yQx6N0HMyXG6/lNC9GalYW5C7MHX+2nAR7K6OQ4nPONrDNITI6W1bIfnm0QrerNonH7yEN5XxUl0oAUEzP/ecdNNwmtP5o8YY/TL5kMp7egKBe3blrUu/ulGy1KTKOfTQ/0+Ynf0fe4EI6wFiYSakoxOXoec/C6Kk+jlk2I1CdcGyA6tPxvBRlBGRtnZyUq1x6WtsLlMRFPx54HqDi80CCfjG51yyLtZ6jLBJLlErwCL26UIfCuMn2vvLi8HrFU4kNVTTbOhRJgWQ2jEYtIZJXB0i5LiD+vZhqz/TKWWn25M3qTcNOxusIukBy1pl5Qd2tSfIf94tXB5e/Mf8fAAD//xXHw3XlAgAA"

  # This secret is enabled for operation. Optionally, there is an option
  # to temporarily disable it.
  enabled = true

  # The secret version cannot be used before this date
  # Needs to be formatted yyyy-mm-ddTHH:MM:SS'Z'
  # not_before_date = "2025-06-14T20:56:08Z"

  # The secret version cannot be used after this date
  # Needs to be formatted yyyy-mm-dd'T'HH:MM:SS'Z'
  # not_after_date = "2026-06-14T20:56:08Z"

  tags = {
    # Fill the tags as desired
    # tagName =  "TagValue"
  }

  destination_secret = {
    name = "example-secret-3"
  }
}