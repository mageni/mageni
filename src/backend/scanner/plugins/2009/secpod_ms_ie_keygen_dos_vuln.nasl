###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_keygen_dos_vuln.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Internet Explorer 'KEYGEN' Element Denial Of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900864");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3267");
  script_name("Internet Explorer 'KEYGEN' Element Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3194/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/EXE/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
Denial of Service.");
  script_tag(name:"affected", value:"Internet Explorer version 6.x to 6.0.2900.2180 and 7.0.6000.16711.");
  script_tag(name:"insight", value:"A CPU consumption error occurs via an automatically submitted form
containing a KEYGEN element.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Internet Explorer and is prone to
Denial of Service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

ieVer = get_kb_item("MS/IE/EXE/Ver");
if(!ieVer){
  exit(0);
}

if(version_is_equal(version:ieVer, test_version:"7.0.6000.16711")||
   version_in_range(version:ieVer, test_version:"6.0",
                                  test_version2:"6.0.2900.2180")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
