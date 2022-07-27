###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_soda_pdf_insecure_lib_load_vuln_win.nasl 31536 2013-09-03 14:36:51Z sep$
#
# Soda PDF Insecure Library Loading Vulnerability (Windows)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################
CPE = "cpe:/a:soda:soda_pdf";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803751");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2013-3485");
  script_bugtraq_id(61727);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-09-03 11:21:22 +0530 (Tue, 03 Sep 2013)");
  script_name("Soda PDF Insecure Library Loading Vulnerability (Windows)");


  script_tag(name:"summary", value:"The host is installed with Soda PDF and is prone to insecure library
loading vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"insight", value:"The flaw is due to the application loading libraries (dwmapi.dll or
api-ms-win-core-localregistry-l1-1-0.dll) in an insecure manner.");
  script_tag(name:"affected", value:"Soda PDF version 5.1.183.10520, Other versions may also be affected.");
  script_tag(name:"impact", value:"Successful exploitation will allow local attacker to execute arbitrary code
and conduct DLL hijacking attacks.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53207");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/86353");
  script_xref(name:"URL", value:"http://forums.cnet.com/7726-6132_102-5486855.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_soda_pdf_detect_win.nasl");
  script_mandatory_keys("Soda/PDF/Ver/Win");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

sodaPdfVer = get_app_version(cpe:CPE);
if(!sodaPdfVer){
  exit(0);
}

if(version_is_equal(version:sodaPdfVer, test_version:"5.1.183.10520"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
