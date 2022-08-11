###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_subversion_buf_overflow_vuln_feb16.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Apache Subversion Buffer Overflow Vulnerability -01 Feb16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806851");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2015-5259");
  script_bugtraq_id(82300);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-04 17:06:21 +0530 (Thu, 04 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Subversion Buffer Overflow Vulnerability -01 Feb16");

  script_tag(name:"summary", value:"This host is installed with Apache Subversion
  and is prone to Buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to

  - an integer overflow in the svn:// protocol parser.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to cause a denial of service or possibly execute arbitrary code under
  the context of the targeted process.");

  script_tag(name:"affected", value:"Subversion 1.9.x before 1.9.3.");

  script_tag(name:"solution", value:"Upgrade to version 1.9.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1034469");
  script_xref(name:"URL", value:"https://subversion.apache.org/security/CVE-2015-5259-advisory.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(!subver = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(subver =~ "^(1\.9)")
{
  if(version_is_less(version:subver, test_version:"1.9.3"))
  {
     report = report_fixed_ver( installed_version:subver, fixed_version:"1.9.3" );
     security_message(data:report, port:http_port);
     exit(0);
  }
}
