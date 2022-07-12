###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_informix_dynamic_server_priv_esc_vuln.nasl 12088 2018-10-25 10:57:43Z cfischer $
#
# IBM Informix Dynamic Server Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:informix_dynamic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808639");
  script_version("$Revision: 12088 $");
  script_cve_id("CVE-2016-0226");
  script_bugtraq_id(85198);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 12:57:43 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-08 13:44:37 +0530 (Mon, 08 Aug 2016)");
  script_name("IBM Informix Dynamic Server Privilege Escalation Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with IBM Informix
  Dynamic Server and is prone to a privilege escalation vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper restrict
  access to the 'nsrd', 'nsrexecd', and 'portmap' executable files in client
  implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users to modify the binary for this service and thus execute code in the
  context of SYSTEM.");

  script_tag(name:"affected", value:"IBM Informix Dynamic Server 11.70.xCn
  on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=630&uid=swg21978598");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_ibm_informix_dynamic_server_detect_win.nasl");
  script_mandatory_keys("IBM/Informix/Dynamic/Server/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

idsVer = get_app_version(cpe:CPE);
if(!idsVer){
  exit(0);
}

if(version_is_equal(version:idsVer, test_version:"11.70"))
{
  report = report_fixed_ver(installed_version:idsVer, fixed_version:"Apply the patch");
  security_message(data:report);
  exit(0);
}
