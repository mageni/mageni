###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kallithea_mult_xss_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Kallithea < 0.2.1 Multiple XSS Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.112058");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2015-1864");
  script_bugtraq_id(74184);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-27 15:00:33 +0200 (Wed, 27 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Kallithea < 0.2.1 Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Kallithea and
    is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"HTML and Javascript injection was possible in several places in the Kallithea UI,
    allowing attackers to run malicious code.

    User details (first name, last name) as well as repository, repository group and user group descriptions were pasted
    unfiltered into the HTML code, thus attacker could inject malicious code.");

  script_tag(name:"impact", value:"As the vulnerability allows attacker to execute arbitrary code in the
    user's browser, it can be used to gain access to the user's account by
    stealing credentials, like API keys. It is also possible for the attacker to gain full
    administrator access to the Kallithea instance.");

  script_tag(name:"affected", value:"Kallithea before version 0.2.1");

  script_tag(name:"solution", value:"Upgrade to Kallithea version 0.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/04/14/12");
  script_xref(name:"URL", value:"https://kallithea-scm.org/security/cve-2015-1864.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kallithea_detect.nasl");
  script_mandatory_keys("Kallithea/Installed");
  script_require_ports("Services/www", 5000);
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

if(version_is_less(version:ver, test_version:"0.2.1"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"0.2.1");
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
