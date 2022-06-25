################################################################################
# OpenVAS Vulnerability Test
#
# Burp Suite 'Collaborator server certificat' Security Bypass Vulnerability (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
################################################################################

CPE = "cpe:/a:portswigger:burp_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813811");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-10377");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-02 13:12:21 +0530 (Thu, 02 Aug 2018)");
  script_name("Burp Suite 'Collaborator server certificat' Security Bypass Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with Burp Suite
  Community Edition and is prone to man in the middle security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exist due to improper validating
  of Collaborator server TLS certificate. It fails to check if the certificate
  CN matches the hostname, making it vulnerable to an active MITM attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  man-in-the-middle attackers to obtain interaction data.");

  script_tag(name:"affected", value:"Burp Suite before 1.7.34 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Burp Suite version 1.7.34 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://releases.portswigger.net/2018/06/1734.html");
  script_xref(name:"URL", value:"https://hackerone.com/reports/337680");
  script_xref(name:"URL", value:"https://portswigger.net");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_burp_suite_ce_detect_lin.nasl");
  script_mandatory_keys("BurpSuite/CE/Linux/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE, nofork: TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"1.7.34"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.7.34", install_path:path);
  security_message(data:report);
  exit(0);
}
