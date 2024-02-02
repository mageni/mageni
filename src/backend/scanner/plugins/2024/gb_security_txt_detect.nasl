# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102093");
  script_version("2024-01-16T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-01-16 05:05:27 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-12 10:28:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("security.txt Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Web Servers can use a file called security.txt to provide
  contact information for security researchers and other security related content.");

  script_tag(name:"vuldetect", value:"Checks if a security.txt is present at the following
  locations:

  /.well-known/security.txt

  /security.txt (Legacy compatibility)

  Note: The file found under well-known is used / reported if both are present.");

  script_tag(name:"insight", value:"Security researchers can use the security.txt file to retrieve
  contact information for security issues related to the URI used to retrieve it. The file may also
  apply to products and services that are offered. The content of the file should be checked
  regularly to ensure that it is up-to-date and that security researchers can trust its content.");

  script_tag(name:"solution", value:"Check the content of the security.txt file and update its
  content, such as the expiration date, to provide up-to-date information that can be trusted.");

  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc9116/");
  script_xref(name:"URL", value:"https://securitytxt.org/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

# n.b. As per https://datatracker.ietf.org/doc/html/rfc9116/#name-location-of-the-securitytxt https is required.
port = http_get_port(default:443);

# n.b well-known path must be used. Legacy compatibility however allows for placement at top-level path
# The file found under well-known must be used if both are present.
foreach url(make_list("/.well-known/security.txt", "/security.txt")) {

  res = http_get_cache(port:port, item:url);

  # n.b From RFC 9116:
  # > It MUST have a Content-Type of "text/plain"
  if(! res || res !~ "^HTTP/1\.[01] 200" || res !~ "Content-Type\s*:\s*text/plain")
    continue;

  body = http_extract_body_from_response(data:res);
  body = chomp(body);
  if(!body)
    continue;

  # n.b
  # - RFC 9116 says that both fields MUST be present for a valid security.txt. But we also want to
  #   catch these not strictly following the RFC and as our Content-Type above should be strict
  #   enough we're using either one of both as a detection point.
  # - It is important that at least "Expires:" is checked in the body only as there is also a
  #   "Expires:" HTTP header field
  if(egrep(string:body, pattern:"^\s*(Expires|Contact)\s*:", icase:TRUE)) {
    report = string("The file '", http_report_vuln_url(url:url, port:port, url_only:TRUE), "' contains the following:\n", body);
    log_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
