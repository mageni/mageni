###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xilisoft_video_conv_bof_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Xilisoft Video Converter Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900630");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1370");
  script_bugtraq_id(34472);
  script_name("Xilisoft Video Converter Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34660");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8452");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49807");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_xilisoft_video_conv_detect.nasl");
  script_mandatory_keys("Xilisoft/Video/Conv/Ver");
  script_tag(name:"impact", value:"This issue can be exploited to corrupt the memory and to execute arbitrary
  code in the context of the affected application.");
  script_tag(name:"affected", value:"Xilisoft Video Converter version 3.x to 3.1.53.0704n and 5.x to 5.1.23.0402
  on Windows.");
  script_tag(name:"insight", value:"The cause is due to an error in ape_plugin.plg when parsing malicious .CUE
  files containing overly long string.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is with installed Xilisoft Video Converter and is prone
  to Buffer Overflow Vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

xsoftVer = get_kb_item("Xilisoft/Video/Conv/Ver");
if(!xsoftVer){
  exit(0);
}

if(version_in_range(version:xsoftVer, test_version:"3.0", test_version2:"3.1.53.0704n") ||
   version_in_range(version:xsoftVer, test_version:"5.0", test_version2:"5.1.23.0402")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
