##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iexplorer_dos_vuln_900131.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: Microsoft Internet Explorer Denial of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900131");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-09-26 07:36:49 +0200 (Fri, 26 Sep 2008)");
  script_cve_id("CVE-2008-4127");
  script_bugtraq_id(31215);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Microsoft Internet Explorer Denial of Service Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.secniche.org/ie_mal_png_dos.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/496483");

  script_tag(name:"summary", value:"The host has Microsoft Internet Explorer installed, which is prone
  to denial of service vulnerability.");

  script_tag(name:"insight", value:"Due to errors while handling PNG files, CDwnTaskExec::ThreadExec enters
  into an infinite loop while loading images which causes the browser to crash. This can be exploited by
  enticing victim to visit a malicious web page embedded with rogue PNG files.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer 7.x and 8 Beta on Windows");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"impact", value:"Successful exploitation will cause the application to stop
  responding and denying the service to legitimate users.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://windows.microsoft.com/en-us/internet-explorer/download-ie");

  exit(0);
}

include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 iExpVer = registry_get_sz(key:"SOFTWARE\Microsoft\Internet Explorer" ,
                           item:"Version");
 if(!iExpVer){
	iExpVer = registry_get_sz(item:"IE",
        	  key:"SOFTWARE\Microsoft\Internet Explorer\Version Vector");
	if(!iExpVer){
        	exit(0);
	}
 }

 if(ereg(pattern:"^(7\..*|8\.0\.(([0-5]?[0-9]?[0-9]?[0-9]|6000)\..*|6001" +
              "\.(0?[0-9]?[0-9]?[0-9]?[0-9]|1[0-7][0-9][0-9][0-9]|18[01]" +
              "[0-9][0-9]|182([0-3][0-9]|4[01]))))($|[^.0-9])", string:iExpVer)){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
 }
