###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_mult_vuln01_july16.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM Websphere Application Server Multiple Vulnerabilities-01 July16
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

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808188");
  script_version("$Revision: 13803 $");
  script_cve_id("CVE-2016-2923", "CVE-2016-2945", "CVE-2016-0389");
  script_bugtraq_id(91517, 91518, 91515);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-07-12 10:51:17 +0530 (Tue, 12 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server Multiple Vulnerabilities-01 July16");

  script_tag(name:"summary", value:"This host is installed with IBM Websphere
  application server and is prone to multiple Vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Multiple flaws are due to

  - The failure of setting the 'HTTPOnly' flag in 'JAX-RS' API.

  - IBM WebSphere Application Server Liberty Profile using the API Discovery
    feature could provide weaker than expected security in 'API Discovery'
    feature when using Swagger documents with external references.

  - An improper handling by the Admin Center.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to obtain sensitive information and also allow a remote
  authenticated users to gain privileges.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  8.5 through 8.5.5.9 Liberty before Liberty Fix Pack 16.0.0.2");

  script_tag(name:"solution", value:"Apply Liberty Fix Pack 16.0.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21983700");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21984502");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21982012");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/liberty/profile/installed");

  script_xref(name:"URL", value:"http://www-03.ibm.com/software/products/en/appserv-was");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:wasVer, test_version:"8.5.0.0", test_version2:"8.5.5.9"))
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:"16.0.0.2");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);