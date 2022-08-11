###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_null_ptr_dos_vuln.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Microsoft Internet Explorer NULL Pointer DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800337");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0072");
  script_bugtraq_id(33149);
  script_name("Microsoft Internet Explorer NULL Pointer DoS Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47788");
  script_xref(name:"URL", value:"http://skypher.com/index.php/2009/01/07/msie-screen-null-ptr-dos-details/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause the application
  to crash.");
  script_tag(name:"affected", value:"Microsoft, Internet Explorer version 6.0, 7.0, 8.0 Beta2 and prior.");
  script_tag(name:"insight", value:"The flaw is due to improper handling of onload=screen[''] attribute
  value in BODY element. By persuading a victim to visit a specially-crafted
  Web page, denial of service can be caused.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host has Internet Explorer installed and is prone to Remote
  Denial of Service vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/windows/products/default.aspx");
  exit(0);
}


include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_in_range(version:ieVer, test_version:"6.0",
                    test_version2:"8.0.6001.18241")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
