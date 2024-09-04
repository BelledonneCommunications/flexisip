/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

namespace flexisip::tester {
constexpr auto kRsaPrivKey = "-----BEGIN RSA PRIVATE KEY-----\n"
                             "MIIJKAIBAAKCAgEAjOqDpkkZmgGTKvPBhdaJg6CrpmeIlPC06ANYpxWpyqkhdUpp"
                             "p172bdj8F790Ty5hiZpWANGpRNv/5wCfS+oCW5bHh+d8vGDjq3pniE7yxslueg14"
                             "wkXOLO1KxaNgnI0MvtDHN3vIFMTbzxcCPfVu+zYK/24nncEQRJbJ+Qnl/4te7q0o"
                             "VoCPhfqwCb3MZtuCqVVgv8QMo6eJSgB1GQnG8vEeVJGVp/Zh5jeTvj9BAT2fhCNo"
                             "J5UvbotVmVdV6p5oT8xch+53EWBzTS61ges5q6pY7I8nc1jxizvOofK6t9P4R34Z"
                             "JPM4cGg19c1y+ie3NVaF6JEo/O58AbTucTSs0i2PEq0pJbJX669tSWUAxm3+qgkE"
                             "PkKOZpJzquoNKAyTmSy4/fty3ZOJAViTjsgWnld5yP67tzuEbJ4m7qxVhvjyS9fO"
                             "lwhhRN2lPLV1mmhew+VPGdqd+RdATdIPQwb2g9kyOzzvIQUUvxwtYjUgxZ0kwpi+"
                             "64lReMPvDzOswAOKs368kjFkKMCrUPVWk5GFm2y3sWY7ylioadmNS4i21WGrYqnY"
                             "+KRdocDFNNtggwrhtDX3BEAuWUSVuxkaGJHCdDK3NfK6UDn4//y5MIznHPZYg5Eu"
                             "WZHvriO6DMKw6p/XWfQQNsqnJrS2N8W+LqRw1J87QskwxutGJq8HsVObovECAwEA"
                             "AQKCAgAZqdYbESIT/ahvQKBkfwthSQAp2J4zvdi8jmt1VokrKv04brpqLG3F2Kgk"
                             "rQ4CI6jI1i5GjOh+bXCgAemA+le+lWm2Uw7RAfZEsxCq7vHhCStRGCX/f5YKcZbW"
                             "AqikKj4BfGVjsevg+G8tunuCjDHPl2qOVWHqpZAQZcPX0pksHpZF8owvoM9Cr8Ki"
                             "q4nPy7dynmV11z8UCP2EWCv7SOAOO6Jx9WejhMgUlNeX5M4yayYjew1LdCyEveRz"
                             "fkfb6EiIC+hoKyJNLFsjWdfdltjUbjwurO2a4L5wxI4fyWR++SA06P6sT41eT2RQ"
                             "ZT/E1jnUAXN2xQUJd2dnKivouxakFVBBOuCqA+4y4rfbgfzdYQQTkhw5+4Mnx7aS"
                             "Nlr7kP+qFM9YLZ/Z70mepb7fDkIuk2IQH4SSF9A674lvrqTAgdcJ7sr3yABxOc+1"
                             "SRdAxLFh/7wvakTKvXx+hcBx5zSuk3m+AGVUjea67QPH1e1n0xKeMEoKDQNC3Pxu"
                             "QEoVsSP2ehYvZ2jotD3CdlOa9rAoAWRwckfdbmrRF0l6+XiZ2c73pj2nQjXI4Yi/"
                             "Jydnu1Kn7Tp8Fcqdr6eZxQCfL3OqejgGWNJT5Nw3x1EB5GqIGnHS4onek6W2GG5o"
                             "mz0+kWF3ogyAKHgjxG+41I5U627IqRp7cBIhSrbfz2q+bYwHjwKCAQEAvvNNo7mU"
                             "QDHLNkhqQA1I7YYv50BwdImtpRv3aOyrEt+SH/FTQqUxOIpT7m1GBordveoKSmT0"
                             "thXZDmi/+r+axWQJKGHeCkyPVliU6eoSqw8itlZmIM9VpYJrAhCbPHf6lrAGVT1A"
                             "Z/Jk7dxU8yhdktytAa09LttvCTmMaJB2E4GsBUSvEY0fFsSolbn+AkUzQUOGn2E6"
                             "t9g+jp25chI7kINv9CKcEbHReUayEZewkR1JCzWrYj9EvrR9kddhUioPEACfmHsD"
                             "FhwUkLpzmD7H0cveqwu8czHtwFUrmeGgZEeccmRuLacIo9kWy99XRJB3g39i6o1k"
                             "fi1NC/rHefD8fwKCAQEAvOu9a3VRlKI7hY68uP4DfnHWPS44IZRNy0kNqk3XzMus"
                             "ROmezBBKmbLeX78e3/R30sMSRDvJLDsdpxesDGaHWRb9VbJPozWCh2s3uDrPtiTb"
                             "YbyGVK7nsBZ9c6X+hqaFZUqcwZ3NdIlc68zNhMcRtb46e9XMya/a/Mvw6qd646f2"
                             "AObyx6L1Q0fmwUQJwE1QmL8UcayzCKa9rWTpEwm5ZC30YNro+oDDpmFQt/LdKbO0"
                             "bWBnQ4VfAhqmMgawFT+I8lB60Nf6jFN5UICl3i5X2Ia9G0/Fdu6H/G4MShcoX5Kt"
                             "rVZp6FUUwWsXbOraYeNiziwwdjQUbnzX1Dhh5xVojwKCAQEAqjSTgxobdHEuEw/P"
                             "bZKp69cNghMlaiuC1cas7SDwiJ0yUji5H5HB4wUiNUfAAHrtlqg0TgXZPykQVlC2"
                             "t1rtKX+2zgEWe5Wsuqmw6yRTSZjvNxqiZCKL1EEBA1EsHmVPv9vdeUNk0oL0xjT8"
                             "n9XeOtdrezAhdk/wlIdwiZAjP9X5MKT9bCafjJr1LqkgKoPmYQlAyXZQcalWcadT"
                             "ssNfxrvyIeprtTYMYw7KEPZmU6OIBW7semGs9FRMDaCvRh7pWDlGCRO1N5MGHc+k"
                             "1BM5597SdyK58vCRXTxN5heA8YIHiMvOjfDyuaH7OPS2hA5GCbeVwz8PUY0tvTzn"
                             "a+GMHwKCAQA0PJamhMzm5SjCGCKUoB/FMaLETehVWJVeFTgDE/0McnCSqWowEH0g"
                             "HHYiUU0vLYCINUnytfk9EqdzUTdQQnVAK/wmWuRsQ1pxKTNB7HkMawqB7sfR2H7V"
                             "kJJljMtg3eBajpPjcUei5mxcAsf847JA53VyUj6KseZCKf3WVDLFieaaf0E39BYO"
                             "4W2rmK19j6MuaP81I0RpqvkdXZ6YlgK98Xr14PG0ejAe7B+OjUebxUWpTJOg9tq7"
                             "UTUM9g5wAZ5TKe+bmWx8qoQLv1adpYDCrRbS227FINVW9fLN9bNDIeKF4DPuer//"
                             "byYOBq4VjPMAAPXxaRsRJdHjqyde5ut/AoIBAGXr7cRprjEQ19YEfaR3f5jKPR6O"
                             "7WUzn143A09oRFiyOObqtokjgj+d4RS+kCPVtqzZfp04O0ccRoLGkrJPj69Qy95E"
                             "QIJ3y2U2WXj+gdVDsFEhhsRtBOTb/ZEoBI4cSNhCRu7It8LZoqa/wcsd9L42gmoR"
                             "ZBZ+a3CG1WLuyqx3pxwdVnqRurj2TVoZ5nhhqYByZyTXJ7WF0Ec6PVbuN5aPXl9/"
                             "AjFcQfBbSAUqxZfo1w8a/u86L7zZ8zU0VbZZx39HTbmCu4agWKv3SgGOl3SlRANR"
                             "WCNh2+Nl1UxAD1DEn3Zbu2zBN/2AeJaSePXlzEHvHwue68fs2ZnNFXIddiQ="
                             "\n-----END RSA PRIVATE KEY-----";

constexpr auto kRsaPubKey = "-----BEGIN PUBLIC KEY-----\n"
                            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjOqDpkkZmgGTKvPBhdaJ"
                            "g6CrpmeIlPC06ANYpxWpyqkhdUppp172bdj8F790Ty5hiZpWANGpRNv/5wCfS+oC"
                            "W5bHh+d8vGDjq3pniE7yxslueg14wkXOLO1KxaNgnI0MvtDHN3vIFMTbzxcCPfVu"
                            "+zYK/24nncEQRJbJ+Qnl/4te7q0oVoCPhfqwCb3MZtuCqVVgv8QMo6eJSgB1GQnG"
                            "8vEeVJGVp/Zh5jeTvj9BAT2fhCNoJ5UvbotVmVdV6p5oT8xch+53EWBzTS61ges5"
                            "q6pY7I8nc1jxizvOofK6t9P4R34ZJPM4cGg19c1y+ie3NVaF6JEo/O58AbTucTSs"
                            "0i2PEq0pJbJX669tSWUAxm3+qgkEPkKOZpJzquoNKAyTmSy4/fty3ZOJAViTjsgW"
                            "nld5yP67tzuEbJ4m7qxVhvjyS9fOlwhhRN2lPLV1mmhew+VPGdqd+RdATdIPQwb2"
                            "g9kyOzzvIQUUvxwtYjUgxZ0kwpi+64lReMPvDzOswAOKs368kjFkKMCrUPVWk5GF"
                            "m2y3sWY7ylioadmNS4i21WGrYqnY+KRdocDFNNtggwrhtDX3BEAuWUSVuxkaGJHC"
                            "dDK3NfK6UDn4//y5MIznHPZYg5EuWZHvriO6DMKw6p/XWfQQNsqnJrS2N8W+LqRw"
                            "1J87QskwxutGJq8HsVObovECAwEAAQ=="
                            "\n-----END PUBLIC KEY-----";

constexpr auto kInvalidRsaPrivKey = "-----BEGIN RSA PRIVATE KEY-----\n"
                                    "MIIJKAIBAAKCAgEAjOqDpkkZmgGTKvPBhdaJg6CrpmeIlPC06ANYpxWpyqkhdUpp"
                                    "p172bdj8F790Ty5hiZpWANGpRNv/5wCfS+oCW5bHh+d8vGDjq3pniE7yxslueg14"
                                    "000000000000000000000000FMTbzxcCPfVu+zYK/24nncEQRJbJ+Qnl/4te7q0o"
                                    "VoCPhfqwCb3MZtuCqVVgv8QMo6eJSgB1GQnG8vEeVJGVp/Zh5jeTvj9BAT2fhCNo"
                                    "J5UvbotVmVdV6p5oT8xch+53EWBzTS61ges5q6pY7I8nc1jxizvOofK6t9P4R34Z"
                                    "JPM4cGg19c1y+ie3NVaF6JEo/O58AbTucTSs0i2PEq0pJbJX669tSWUAxm3+qgkE"
                                    "PkKOZpJzquoNKAyTmSy4/fty3ZOJAViTjsgWnld5yP67tzuEbJ4m7qxVhvjyS9fO"
                                    "lwhhRN2lPLV1mmhew+VPGdqd+RdATdIPQwb2g9kyOzzvIQUUvxwtYjUgxZ0kwpi+"
                                    "64lReMPvDzOswAOKs368kjFkKMCrUPVWk5GFm2y3sWY7ylioadmNS4i21WGrYqnY"
                                    "+KRdocDFNNtggwrhtDX3BEAuWUSVuxkaGJHCdDK3NfK6UDn4//y5MIznHPZYg5Eu"
                                    "WZHvriO6DMKw6p/XWfQQNsqnJrS2N8W+LqRw1J87QskwxutGJq8HsVObovECAwEA"
                                    "AQKCAgAZqdYbESIT/ahvQKBkfwthSQAp2J4zvdi8jmt1VokrKv04brpqLG3F2Kgk"
                                    "rQ4CI6jI1i5GjOh+bXCgAemA+le+lWm2Uw7RAfZEsxCq7vHhCStRGCX/f5YKcZbW"
                                    "AqikKj4BfGVjsevg+G8tunuCjDHPl2qOVWHqpZAQZcPX0pksHpZF8owvoM9Cr8Ki"
                                    "q4nPy7dynmV11z8UCP2EWCv7SOAOO6Jx9WejhMgUlNeX5M4yayYjew1LdCyEveRz"
                                    "fkfb6EiIC+hoKyJNLFsjWdfdltjUbjwurO2a4L5wxI4fyWR++SA06P6sT41eT2RQ"
                                    "ZT/E1jnUAXN2xQUJd2dnKivouxakFVBBOuCqA+4y4rfbgfzdYQQTkhw5+4Mnx7aS"
                                    "Nlr7kP+qFM9YLZ/Z70mepb7fDkIuk2IQH4SSF9A674lvrqTAgdcJ7sr3yABxOc+1"
                                    "SRdAxLFh/7wvakTKvXx+hcBx5zSuk3m+AGVUjea67QPH1e1n0xKeMEoKDQNC3Pxu"
                                    "QEoVsSP2ehYvZ2jotD3CdlOa9rAoAWRwckfdbmrRF0l6+XiZ2c73pj2nQjXI4Yi/"
                                    "Jydnu1Kn7Tp8Fcqdr6eZxQCfL3OqejgGWNJT5Nw3x1EB5GqIGnHS4onek6W2GG5o"
                                    "mz0+kWF3ogyAKHgjxG+41I5U627IqRp7cBIhSrbfz2q+bYwHjwKCAQEAvvNNo7mU"
                                    "QDHLNkhqQA1I7YYv50BwdImtpRv3aOyrEt+SH/FTQqUxOIpT7m1GBordveoKSmT0"
                                    "thXZDmi/+r+axWQJKGHeCkyPVliU6eoSqw8itlZmIM9VpYJrAhCbPHf6lrAGVT1A"
                                    "Z/Jk7dxU8yhdktytAa09LttvCTmMaJB2E4GsBUSvEY0fFsSolbn+AkUzQUOGn2E6"
                                    "t9g+jp25chI7kINv9CKcEbHReUayEZewkR1JCzWrYj9EvrR9kddhUioPEACfmHsD"
                                    "FhwUkLpzmD7H0cveqwu8czHtwFUrmeGgZEeccmRuLacIo9kWy99XRJB3g39i6o1k"
                                    "fi1NC/rHefD8fwKCAQEAvOu9a3VRlKI7hY68uP4DfnHWPS44IZRNy0kNqk3XzMus"
                                    "ROmezBBKmbLeX78e3/R30sMSRDvJLDsdpxesDGaHWRb9VbJPozWCh2s3uDrPtiTb"
                                    "YbyGVK7nsBZ9c6X+hqaFZUqcwZ3NdIlc68zNhMcRtb46e9XMya/a/Mvw6qd646f2"
                                    "AObyx6L1Q0fmwUQJwE1QmL8UcayzCKa9rWTpEwm5ZC30YNro+oDDpmFQt/LdKbO0"
                                    "bWBnQ4VfAhqmMgawFT+I8lB60Nf6jFN5UICl3i5X2Ia9G0/Fdu6H/G4MShcoX5Kt"
                                    "rVZp6FUUwWsXbOraYeNiziwwdjQUbnzX1Dhh5xVojwKCAQEAqjSTgxobdHEuEw/P"
                                    "bZKp69cNghMlaiuC1cas7SDwiJ0yUji5H5HB4wUiNUfAAHrtlqg0TgXZPykQVlC2"
                                    "t1rtKX+2zgEWe5Wsuqmw6yRTSZjvNxqiZCKL1EEBA1EsHmVPv9vdeUNk0oL0xjT8"
                                    "n9XeOtdrezAhdk/wlIdwiZAjP9X5MKT9bCafjJr1LqkgKoPmYQlAyXZQcalWcadT"
                                    "ssNfxrvyIeprtTYMYw7KEPZmU6OIBW7semGs9FRMDaCvRh7pWDlGCRO1N5MGHc+k"
                                    "1BM5597SdyK58vCRXTxN5heA8YIHiMvOjfDyuaH7OPS2hA5GCbeVwz8PUY0tvTzn"
                                    "a+GMHwKCAQA0PJamhMzm5SjCGCKUoB/FMaLETehVWJVeFTgDE/0McnCSqWowEH0g"
                                    "HHYiUU0vLYCINUnytfk9EqdzUTdQQnVAK/wmWuRsQ1pxKTNB7HkMawqB7sfR2H7V"
                                    "kJJljMtg3eBajpPjcUei5mxcAsf847JA53VyUj6KseZCKf3WVDLFieaaf0E39BYO"
                                    "4W2rmK19j6MuaP81I0RpqvkdXZ6YlgK98Xr14PG0ejAe7B+OjUebxUWpTJOg9tq7"
                                    "UTUM9g5wAZ5TKe+bmWx8qoQLv1adpYDCrRbS227FINVW9fLN9bNDIeKF4DPuer//"
                                    "byYOBq4VjPMAAPXxaRsRJdHjqyde5ut/AoIBAGXr7cRprjEQ19YEfaR3f5jKPR6O"
                                    "7WUzn143A09oRFiyOObqtokjgj+d4RS+kCPVtqzZfp04O0ccRoLGkrJPj69Qy95E"
                                    "QIJ3y2U2WXj+gdVDsFEhhsRtBOTb/ZEoBI4cSNhCRu7It8LZoqa/wcsd9L42gmoR"
                                    "ZBZ+a3CG1WLuyqx3pxwdVnqRurj2TVoZ5nhhqYByZyTXJ7WF0Ec6PVbuN5aPXl9/"
                                    "AjFcQfBbSAUqxZfo1w8a/u86L7zZ8zU0VbZZx39HTbmCu4agWKv3SgGOl3SlRANR"
                                    "WCNh2+Nl1UxAD1DEn3Zbu2zBN/2AeJaSePXlzEHvHwue68fs2ZnNFXIddiQ="
                                    "\n-----END RSA PRIVATE KEY-----";

constexpr auto kRsaCert = "-----BEGIN CERTIFICATE-----\n"
                          "MIIGFTCCA/2gAwIBAgIUUbn6ugzuuXt5sheFqyha0W231tcwDQYJKoZIhvcNAQEL"
                          "BQAwgZgxCzAJBgNVBAYTAktBMRIwEAYDVQQIDAlDYXJtZWxpZGUxEjAQBgNVBAcM"
                          "CUthYW1lbG90dDETMBEGA1UECgwKUm91bmRUYWJsZTEOMAwGA1UECwwFR3JhYWwx"
                          "DzANBgNVBAMMBkFydGh1cjErMCkGCSqGSIb3DQEJARYcYXJ0aHVyLnBlbmRyYWdv"
                          "bkBleGFtcGxlLm9yZzAgFw0yNDA1MTQxNDM1NTdaGA8zMDA0MDcxNjE0MzU1N1ow"
                          "gZgxCzAJBgNVBAYTAktBMRIwEAYDVQQIDAlDYXJtZWxpZGUxEjAQBgNVBAcMCUth"
                          "YW1lbG90dDETMBEGA1UECgwKUm91bmRUYWJsZTEOMAwGA1UECwwFR3JhYWwxDzAN"
                          "BgNVBAMMBkFydGh1cjErMCkGCSqGSIb3DQEJARYcYXJ0aHVyLnBlbmRyYWdvbkBl"
                          "eGFtcGxlLm9yZzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIzqg6ZJ"
                          "GZoBkyrzwYXWiYOgq6ZniJTwtOgDWKcVqcqpIXVKaade9m3Y/Be/dE8uYYmaVgDR"
                          "qUTb/+cAn0vqAluWx4fnfLxg46t6Z4hO8sbJbnoNeMJFziztSsWjYJyNDL7Qxzd7"
                          "yBTE288XAj31bvs2Cv9uJ53BEESWyfkJ5f+LXu6tKFaAj4X6sAm9zGbbgqlVYL/E"
                          "DKOniUoAdRkJxvLxHlSRlaf2YeY3k74/QQE9n4QjaCeVL26LVZlXVeqeaE/MXIfu"
                          "dxFgc00utYHrOauqWOyPJ3NY8Ys7zqHyurfT+Ed+GSTzOHBoNfXNcvontzVWheiR"
                          "KPzufAG07nE0rNItjxKtKSWyV+uvbUllAMZt/qoJBD5CjmaSc6rqDSgMk5ksuP37"
                          "ct2TiQFYk47IFp5Xecj+u7c7hGyeJu6sVYb48kvXzpcIYUTdpTy1dZpoXsPlTxna"
                          "nfkXQE3SD0MG9oPZMjs87yEFFL8cLWI1IMWdJMKYvuuJUXjD7w8zrMADirN+vJIx"
                          "ZCjAq1D1VpORhZtst7FmO8pYqGnZjUuIttVhq2Kp2PikXaHAxTTbYIMK4bQ19wRA"
                          "LllElbsZGhiRwnQytzXyulA5+P/8uTCM5xz2WIORLlmR764jugzCsOqf11n0EDbK"
                          "pya0tjfFvi6kcNSfO0LJMMbrRiavB7FTm6LxAgMBAAGjUzBRMB0GA1UdDgQWBBTp"
                          "tgevWjeagdObDZebKyXgg+O2gjAfBgNVHSMEGDAWgBTptgevWjeagdObDZebKyXg"
                          "g+O2gjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQBaxhKDud9C"
                          "gJlS84YZRAZIIu4MtVeMC28onTOt9Y5eV75fIRU98kAOkFs9rlHvGTeqIc9MT/Yw"
                          "bRM4ZHd19VIgAVR9x+3EZaEyTW7h1CgJFeHrytFFx0qiy60GNzKNEgH/wWC51TA1"
                          "CFVNl1t6te5tS1VXsY6H8vzExM/QC2hbVhEBFNmy06oy4yIMTgJB3dxiuZ9Dt47n"
                          "VGicNBu3V+2KP4w2P79E3VS+3v+hJn4VlVu4bY0urzhHBWKtqILoU4b6lndHDNmz"
                          "jBVOnbPi1ZSKDmMIpEZz+SKx9hcMiluKUKD1zcupkBn0yf1qywmHztkHbhdeoOSU"
                          "1ANsMJP1jR0gVPuMSkcswi3CPAo804Vrpv+1lyCY16R4vpZp7N4Q+f/plvKiINIx"
                          "HnqHgKQKHK+lgBJmEMtne203Bq7ccUWKzd+JCWGv33/tV7xARXNKkkTKniqtazfq"
                          "2IYH+UU7wljjqLp5r253X9T1rxZ/k/GyxGGhft1nCuqv0cO//kAqKu1h+PsRdP8O"
                          "AkeOyGZ4+IZp8M5MygiSitr/tpCaXrCfuIypK8jrLKagBNaIH3Pyl5iowule4R3q"
                          "UGN4szQp2BuAAmyXVO+ehaggF2uMuE/A0J1bz170aflh/AcDfpAu/4RaOpLMqQ34"
                          "kqsm5JjLEH4FlHAtFvovXD99n+w5wPWuDg=="
                          "\n-----END CERTIFICATE-----";

} // namespace flexisip::tester