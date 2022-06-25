###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_subversion_mult_vuln_may16.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Apache Subversion Multiple Vulnerabilities May-16
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
  script_oid("1.3.6.1.4.1.25623.1.0.807684");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2015-5343");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-02 15:57:20 +0530 (Mon, 02 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Subversion Multiple Vulnerabilities May-16");

  script_tag(name:"summary", value:"This host is installed with Apache Subversion
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to an integer
  overflow in 'util.c' script in mod_dav_svn when parsing skel-encoded request
  bodies.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to cause a denial of service and to possibly execute arbitrary code
  under the context of the httpd process.");

  script_tag(name:"affected", value:"Apache subversion version 1.7.0 to 1.8.14,
  and 1.9.0 through 1.9.2");

  script_tag(name:"solution", value:"Upgrade to Apache subversion version 1.8.15,
  or 1.9.3, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2015-5343-advisory.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_subversion_remote_detect.nasl");
  script_mandatory_keys("Subversion/installed");
  script_require_ports("Services/www", 3690);
  script_xref(name:"URL", value:"https://subversion.apache.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!sub_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!subver = get_app_version(cpe:CPE, port:sub_port)){
  exit(0);
}

if(version_in_range(version:subver, test_version:"1.9.0", test_version2:"1.9.2"))
{
  fix = "1.9.3";
  VULN = TRUE;
}

else if(version_in_range(version:subver, test_version:"1.7.0", test_version2:"1.8.14"))
{
  fix = "1.8.15";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:subver, fixed_version:fix);
  security_message(data:report, port:sub_port);
  exit(0);
}
