##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sitefinity_mult_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Sitefinity < 10.1 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:progress:sitefinity';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112222");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-13 13:52:34 +0100 (Tue, 13 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2017-18175", "CVE-2017-18176", "CVE-2017-18177", "CVE-2017-18178", "CVE-2017-18179");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sitefinity < 10.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sitefinity_detect.nasl");
  script_mandatory_keys("sitefinity/detected");

  script_tag(name:"summary", value:"Sitefinity is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:'Sitefinity is prone to the following vulnerabilities:

1) Open Redirect Vulnerabilities
Several scripts of Sitefinity are vulnerable to an open redirect. This
vulnerability allows an attacker to redirect the victim to any site by using a
manipulated link (e.g. a manipulated link in a phishing mail, forum or a
guestbook).

The redirection target could imitate the original site and might
be used for phishing attacks or for running browser exploits to infect the
victimas machine with malware. Because the server name in the manipulated link
is identical to the original site, phishing attempts have a more trustworthy
appearance.

In the first instance of this vulnerability, the open redirect will forward
an authentication token to the attacker controlled site, which can be abused
by the attacker to initiate new sessions for the affected user.

2) Broken Session Management
During the authentication process, Sitefinity creates an authentication token
"wrap_access_token", which is further used as a GET parameter to initiate a
valid session if the supplied credentials have been verified to be correct.
Transporting this token as GET parameter causes unnecessary exposure of the
sensitive token, as it might end up in proxy or access logs.

Furthermore, this token is not tied to the session ID and can be used to
generate new valid sessions for the user, even if the initial session has been
terminated by the user.

The token will also survive a password change (e.g. if
the user suspects misuse of his account) and can still be used to initiate new
sessions. During the timeframe of testing, no expiry of the token could be
observed. The wrap_access_token can thus be seen as a "Kerberos golden ticket"
for Sitefinity.

3) Permanent Cross-Site Scripting
Multiple scripts do not properly sanitize/encode user input, which leads to
permanent cross site scripting vulnerabilities.

Furthermore, the web application allows users to upload HTML files,
which are provided via the same domain, allowing an authenticated attacker
to access arbitrary information and execute arbitrary functions of Sitefinity on behalf of other users.
These vulnerabilities can be used by attackers to circumvent segregation of duties.');

  script_tag(name:"affected", value:"Sitefinity before version 10.1.");

  script_tag(name:"solution", value:"Update to version 10.1 or later.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/en/blog/advisories/multiple-vulnerabilities-in-progress-sitefinity/index.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
