# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest

from self_signed_certificates import parse_ca_chain


class TestSelfSignedCertificates:
    def test_given_correct_ca_chain_when_parse_ca_chain_then_list_of_certificates_is_returned(
        self,
    ):
        with open("tests/ca_chain.pem", "r") as f:
            file_content = f.read()

        parsed_ca_chain = parse_ca_chain(file_content)

        assert parsed_ca_chain == [
            (
                "-----BEGIN CERTIFICATE-----\n"
                "MIIDOzCCAiOgAwIBAgIUFrWP+9/yAfKCJ4wt+8G16Z00NwcwDQYJKoZIhvcNAQEL\n"
                "BQAwLTELMAkGA1UEBhMCVVMxHjAcBgNVBAMMFXJvb3RjYS55b3VyZG9tYWluLmNv\n"
                "bTAeFw0yMjA3MDYxNTIwMjhaFw0zMjA3MDMxNTIwMjhaMC0xCzAJBgNVBAYTAlVT\n"
                "MR4wHAYDVQQDDBVyb290Y2EueW91cmRvbWFpbi5jb20wggEiMA0GCSqGSIb3DQEB\n"
                "AQUAA4IBDwAwggEKAoIBAQCChauUqFfey9B3JyRZOxH1T8LkeCgzBgQwfCpNAoKo\n"
                "xVhZbquBBxx2YAM5jgLkIvGnZQ2yaZ94c/R9GeTeKJt4jYPj+Qxevt0Wg2Q4jBQW\n"
                "eAl+cBiq9uC9kpyv+/G7SJtItRBBcwtEznaGfN3ZQvHlxzRWH3alFo1iwc6E9IwZ\n"
                "EQKkVW1bkdN4a+W7Sr670nBvGfVZCDLoH0P4uKmbcCFo7aeuJt4GJlcK6UfCiBBB\n"
                "QIJDgF4HfOeBC/2UeZGHIOBxzYsq6m8dfCLGofglb6uaAeUB+6Q5wHQ4CTeWzpds\n"
                "9OyTKwjsFKCSnpUkWFZCslbf4X61/pgkv1ZEuxLRFGMTAgMBAAGjUzBRMB0GA1Ud\n"
                "DgQWBBR26Cx527A2QEnuF5l/YPGu22oBQzAfBgNVHSMEGDAWgBR26Cx527A2QEnu\n"
                "F5l/YPGu22oBQzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA5\n"
                "r3s8sqHH9gsqW83OX0cJFP4skqsP/QEb2Q0iPGjh3srXRQn4UtY1/5Ti37+XRVE2\n"
                "7QnBEJ+FJYVCc9+R4KRsCi77jUgugBa6+GJ6kLPkCpzbg9qGoaTxbBhpEbbnNFK8\n"
                "hre4I4VKNrjXPyxZ02JgvAEpU6dYoEBvuVNBBuIZkXCGC9zFmSAnx8lQhldE04d8\n"
                "HYDfiasYMLKjTzLQmWGMWeo7tQyDBeCuKgcrpusGTE7y6ohj+w5MxcGoBRRPZ3jh\n"
                "YegJBk9w6phj73tzMBuj5qIvVCTG2/BF2f6Artk43s9tx1PXAj03hplW8i7XB3ua\n"
                "eTqJHx5C3sUyBKoieXJq\n"
                "-----END CERTIFICATE-----"
            ),
            (
                "-----BEGIN CERTIFICATE-----\n"
                "MIIDnTCCAoWgAwIBAgIUGlm3wXnLUA/o4F4b/jr17cgeOKwwDQYJKoZIhvcNAQEL\n"
                "BQAwLTELMAkGA1UEBhMCVVMxHjAcBgNVBAMMFXJvb3RjYS55b3VyZG9tYWluLmNv\n"
                "bTAeFw0yMjA3MDYxNTIwMjhaFw0yNDEwMDgxNTIwMjhaMCgxCzAJBgNVBAYTAlVT\n"
                "MRkwFwYDVQQDDBAqLnlvdXJkb21haW4uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
                "AQ8AMIIBCgKCAQEAplmwyXOi/0Ljwwx7LPCv3xT2EZ1ngKyBlGn8iD+YgxynMr46\n"
                "KiwhS8Mbj0WCo7tx3dTZAtTUd/p+dfmpqphhv1nq/im5g3lAMeIQd8cgUtcJqrpi\n"
                "FQvor1Bm1qF6Y1q4pA4EOxyDhejjLVtcn0xYZxB7BYTRp1L9ZK0qv/fdwCs0TQwq\n"
                "uObSiMIQxvuGEnCw5dN0BUnqZ0juBUQFMT2Z3RFSNx0vXJW+4z10Nwz4D0fRUkXV\n"
                "n6TrWu/M3osvGLjNqmYQ6owV2wQlOy5b5cUfa1vcS0brhSd3E7w9fhYwXAD47vhF\n"
                "jncub9knNahZRSzSLfUB+1MzADNCWx9OwTJpTQIDAQABo4G5MIG2MAkGA1UdEwQC\n"
                "MAAwaQYDVR0RBGIwYIIQKi55b3VyZG9tYWluLmNvbYIUKi5ubXMueW91cmRvbWFp\n"
                "bi5jb22CGCouc3RhZ2luZy55b3VyZG9tYWluLmNvbYIcKi5ubXMuc3RhZ2luZy55\n"
                "b3VyZG9tYWluLmNvbTAdBgNVHQ4EFgQUxzl/AEaI47LsJwnJINk4ZLOZcNswHwYD\n"
                "VR0jBBgwFoAUdugseduwNkBJ7heZf2DxrttqAUMwDQYJKoZIhvcNAQELBQADggEB\n"
                "AACEEv0giGxus/Bwtnb3pGKa5mu7bQPamT0DhBq6qwl8xPp6dP93tDJaF8QaKHMq\n"
                "54TvOPTWLFVOMJQZJDlBVyEjB8NrQeiZZiXPVgPTyiT5DmArO5fCsqB7JvPZqM2K\n"
                "fd1ftXRpxKxzTNzpLUvcjbkLuaAlXaEUU/bu5XSYhUxxcDdCoxlVoBE3rNJOCAdX\n"
                "QIRYjBWEvjWyX5ZT1oNIJK2QO+dbafwpXWs6WITt5BPO9k/sbkBJhA8ztxofEBr0\n"
                "EANWJ/0DpvCzOqbdsBDYpceQjbTwYl9lMLP+3b8TC52E/dseEmKlHahF+K6dlp99\n"
                "UBwM4xo+z6onwTr+vUfXNHI=\n"
                "-----END CERTIFICATE-----"
            ),
        ]

    def test_given_empty_ca_chain_when_parse_ca_chain_then_value_error_is_raised(self):
        with pytest.raises(ValueError) as e:
            parse_ca_chain("")

        assert e.value.args[0] == "No certificate found in chain file"

    def test_given_badly_formatted_ca_chain_when_parse_ca_chain_then_value_error_is_raised(self):
        with pytest.raises(ValueError) as e:
            parse_ca_chain("-----END CERTIFICATE-----")

        assert e.value.args[0] == "No certificate found in chain file"
