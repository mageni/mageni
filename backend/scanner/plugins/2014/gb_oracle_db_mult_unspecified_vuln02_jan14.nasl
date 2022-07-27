###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_mult_unspecified_vuln02_jan14.nasl 11830 2018-10-11 06:12:56Z cfischer $
#
# Oracle Database Server Multiple Unspecified Vulnerabilities-02 Jan2014
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:oracle:database_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804228");
  script_version("$Revision: 11830 $");
  script_cve_id("CVE-2013-5858", "CVE-2014-0377", "CVE-2014-0378");
  script_bugtraq_id(64820, 64824, 64812);
  script_tag(name:"cvss_base", value:"4.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 08:12:56 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-24 14:59:13 +0530 (Fri, 24 Jan 2014)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities-02 Jan2014");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_mandatory_keys("OracleDatabaseServer/installed");
  script_dependencies("oracle_tnslsnr_version.nasl");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56452");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html");

  script_tag(name:"summary", value:"This host is installed with Oracle Database Server and is prone to multiple
  information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist in Core RDBMS and Spatial component, no further
  information available at this moment.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service
  condition or obtain sensitive information.");

  script_tag(name:"affected", value:"Oracle Database Server version 11.1.0.7, 11.2.0.3, 11.2.0.4, and 12.1.0.1
  are affected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!ver = get_app_version(cpe:CPE, port:port)) exit(0);

if(ver =~ "^(11\.[1|2]\.0|12\.1\.0)"){
  if(version_in_range(version:ver, test_version:"11.2.0.3", test_version2:"11.2.0.4") ||
     version_is_equal(version:ver, test_version:"12.1.0.1") ||
     version_is_equal(version:ver, test_version:"11.1.0.7")){
    report = report_fixed_ver(installed_version:ver, fixed_version:"See references for available updates.");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);