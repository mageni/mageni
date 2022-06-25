###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kallithea_mult_remote_vuln.nasl 11959 2018-10-18 10:33:40Z mmartin $
#
# Kallithea < 0.3.2 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:kallithea:kallithea";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112057");
  script_version("$Revision: 11959 $");
  script_cve_id("CVE-2016-3691", "CVE-2016-3114");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:33:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-27 14:30:52 +0200 (Wed, 27 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Kallithea < 0.3.2 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Kallithea and
    is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following issues exist:

  - Routes allow GET requests to override the HTTP method which breaks
    the Kallithea CSRF-protection (which only applies to POST requests).

    The attacker might misuse GET requests method overriding to trick users
    into issuing a request with a different method, thus bypassing the
    CSRF protection.

  - A vulnerability that allows logged-in users to edit or
    delete open pull requests associated with any repository to which
    they have read access, plus a related vulnerability allowing logged-in
    users to delete any comments from any repository, provided they could
    determine the comment ID and had read access to just one repository.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users:

  - to edit or delete open pull requests or delete comments by leveraging read access.

  - to bypass the CSRF protection by using the GET HTTP request method.");

  script_tag(name:"affected", value:"Kallithea before version 0.3.2");

  script_tag(name:"solution", value:"Upgrade to Kallithea version 0.3.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/05/02/3");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kallithea_detect.nasl");
  script_mandatory_keys("Kallithea/Installed");
  script_require_ports("Services/www", 5000);
  script_xref(name:"URL", value:"https://kallithea-scm.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(version_is_less(version:ver, test_version:"0.3.2"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"0.3.2");
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
