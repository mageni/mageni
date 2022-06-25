# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:squid-cache:squid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143765");
  script_version("2020-04-24T08:03:03+0000");
  script_tag(name:"last_modification", value:"2020-04-24 10:04:10 +0000 (Fri, 24 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-24 07:57:13 +0000 (Fri, 24 Apr 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-12520");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Proxy Cache < 4.10 Cache Poisoning Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_squid_detect.nasl");
  script_mandatory_keys("squid_proxy_server/installed");

  script_tag(name:"summary", value:"Squid is prone to a cache poisoning vulnerability.");

  script_tag(name:"insight", value:"When receiving a request, Squid checks its cache to see if it can serve up a
  response. It does this by making a MD5 hash of the absolute URL of the request. If found, it servers the request.
  The absolute URL can include the decoded UserInfo (username and password) for certain protocols. This decoded
  info is prepended to the domain. This allows an attacker to provide a username that has special characters to
  delimit the domain, and treat the rest of the URL as a path or query string. An attacker could first make a
  request to their domain using an encoded username, then when a request for the target domain comes in that
  decodes to the exact URL, it will serve the attacker's HTML instead of the real HTML. On Squid servers that also
  act as reverse proxies, this allows an attacker to gain access to features that only reverse proxies can use,
  such as ESI.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Squid versions prior to 4.10.");

  script_tag(name:"solution", value:"Update to version 4.10 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/jeriko.one/security/-/blob/master/squid/CVEs/CVE-2019-12520.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.10");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
