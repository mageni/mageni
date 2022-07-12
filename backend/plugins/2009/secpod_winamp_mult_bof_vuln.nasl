###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winamp_mult_bof_vuln.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# Winamp AIFF File Multiple Buffer Overflow Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.900197");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0263");
  script_bugtraq_id(33226);
  script_name("Winamp AIFF File Multiple Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/7742");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33478");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  script_tag(name:"impact", value:"Attackers may leverage this issue by executing arbitrary codes in the context
  of the affected application and can execute denial of service attacks on the
  application.");
  script_tag(name:"affected", value:"Winamp version 5.541 and prior on Windows");
  script_tag(name:"insight", value:"Application fails to play a large Common Chunk (COMM) header value in an AIFF
  file and a large invalid value in an MP3 file.");
  script_tag(name:"solution", value:"Upgrade to Winamp version 5.57 or later.");
  script_tag(name:"summary", value:"This host is installed with Winamp and is prone to Buffer Overflow
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.winamp.com");
  exit(0);
}


include("version_func.inc");

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

if(version_is_less_equal(version:winampVer, test_version:"5.5.4.2165")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
