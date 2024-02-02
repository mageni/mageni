# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151295");
  script_version("2024-01-22T05:07:31+0000");
  script_tag(name:"last_modification", value:"2024-01-22 05:07:31 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-11-23 04:46:15 +0000 (Thu, 23 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-02 00:22:00 +0000 (Sat, 02 Dec 2023)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-49103", "CVE-2023-49282");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud Information Disclosure Vulnerability (Nov 2023) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"ownCloud is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The 'graphapi' app relies on a third-party library that
  provides a URL. When this URL is accessed, it reveals the configuration details of the PHP
  environment (phpinfo). This information includes all the environment variables of the webserver.
  In containerized deployments, these environment variables may include sensitive data such as the
  ownCloud admin password, mail server credentials, and license key.

  Note: This issue consists of two different flaws with different severities:

  - CVE-2023-49282: A general phpinfo() information disclosure in the used Microsoft Graph PHP SDK
  which contains sensitive information about the environment usually rated with a 'medium' severity

  - CVE-2023-49103: An environmental variable disclosure specific to ownCloud docker containers
  rated with a 'high' severity");

  script_tag(name:"affected", value:"All ownCloud instances shipping (don't need to be enabled) the
  Graph API app in versions 0.2.0 through 0.3.0.

  Note: Some ownCloud Docker images (e.g. version 10.13.0) have the phpinfo function already added
  to the disable_functions of PHP and are thus not vulnerable.");

  script_tag(name:"solution", value:"There are multiple solutions:

  - Update the Graph API app to version 0.3.1 or later (e.g. via the Marketplace)

  - Delete the file `/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php` from the
  ownCloud installation folder

  - Update to ownCloud 10.3.1 or later which is shipping the updated version 0.3.1 of the Graph API
  app");

  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/disclosure-of-sensitive-credentials-and-configuration-in-containerized-deployments/");
  script_xref(name:"URL", value:"https://github.com/creacitysec/CVE-2023-49103");
  script_xref(name:"URL", value:"https://www.labs.greynoise.io/grimoire/2023-11-29-owncloud-redux/");
  script_xref(name:"URL", value:"https://www.ambionics.io/blog/owncloud-cve-2023-49103-cve-2023-49105");
  script_xref(name:"URL", value:"https://github.com/microsoftgraph/msgraph-sdk-php/security/advisories/GHSA-cgwq-6prq-8h9q");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

urls = make_list(
  # For all instances / installations NOT having index.php-less URLs enabled
  dir + "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php",
  # nb:
  # - For all instances / installations having index.php-less URLs enabled
  # - We're trying two different endpoints here just to be sure
  dir + "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.css",
  dir + "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.js"
);

foreach url (urls) {

  req = http_get(item: url, port: port);
  res = http_keepalive_send_recv(port: port, data: req);
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if (concl = http_check_for_phpinfo_output(data: res)) {
    report = http_report_vuln_url(port: port, url: url);
    report += '\nConcluded from:\n' + concl;

    # <tr><td class="e">$_ENV['OWNCLOUD_ADMIN_USERNAME']</td><td class="v">admin</td></tr>
    if (env_vars = egrep(string: res, pattern: "ENV.+OWNCLOUD_.+", icase: FALSE)) {
      env_vars = chomp(env_vars);
      report += '\n\nThe following possible sensitive ownCloud specific environment variables have been identified:\n\n' + env_vars;
    }

    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
