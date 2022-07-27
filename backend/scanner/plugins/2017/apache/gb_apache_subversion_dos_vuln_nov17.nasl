###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_subversion_dos_vuln_nov17.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Apache Subversion Denial of Service Vulnerability - Nov17
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:apache:subversion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811983");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2013-4246");
  script_bugtraq_id(101620);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-08 18:27:59 +0530 (Wed, 08 Nov 2017)");
  ## Only FSFS repositories created with Subversion 1.8 or upgraded to
  ## 1.8 format (using 'svnadmin upgrade') are affected.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Subversion Denial of Service Vulnerability - Nov17");

  script_tag(name:"summary", value:"This host is installed with Apache Subversion
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a failure to handle
  exceptional conditions.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Apache Subversion 1.8.x before 1.8.2");

  script_tag(name:"solution", value:"Upgrade to version 1.8.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://subversion.apache.org/security/CVE-2013-4246-advisory.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_subversion_remote_detect.nasl");
  script_mandatory_keys("Subversion/installed");
  script_require_ports("Services/www", 3690);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:http_port, exit_no_version:TRUE)) exit(0);
subver = infos['version'];
subPath = infos['location'];

if(subver =~ "^(1\.8)" && version_is_less(version:subver, test_version:"1.8.2"))
{
  report = report_fixed_ver( installed_version:subver, fixed_version:"1.8.2", install_path:subPath);
  security_message(data:report, port:http_port);
  exit(0);
}
exit(0);
