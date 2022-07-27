###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_soliddb_select_statement_dos_vuln.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# IBM solidDB 'SELECT' Statement Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
CPE = "cpe:/a:ibm:soliddb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803763");
  script_version("$Revision: 11883 $");
  script_cve_id("CVE-2011-4890");
  script_bugtraq_id(51629);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-23 15:49:43 +0530 (Mon, 23 Sep 2013)");
  script_name("IBM solidDB 'SELECT' Statement Denial Of Service Vulnerability");


  script_tag(name:"summary", value:"This host is running IBM solidDB and is prone to denial of service
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade IBM solidDB to 6.5 FP9, 7.0 FP1 or later.");
  script_xref(name:"URL", value:"http://www-03.ibm.com/software/products/us/en/ibmsoli");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error when handling a SELECT statement
containing a rownum condition with a subquery.");
  script_tag(name:"affected", value:"IBM solidDB 6.5 before FP9 and 7.0 before FP1");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47654");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72651");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1026555");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC79861");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC80675");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_soliddb_detect.nasl");
  script_mandatory_keys("IBM-soliddb/installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ibmPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ibmVer = get_app_version(cpe:CPE, port:ibmPort)){
  exit(0);
}

if(ibmVer =~ "^6\.5\.*")
{
  if(version_is_less(version:ibmVer, test_version:"6.5.0.9"))
  {
    security_message(port:ibmPort);
    exit(0);
  }
}

if(version_is_equal(version:ibmVer, test_version:"7.0.0.0")){
  security_message(port:ibmPort);
}
