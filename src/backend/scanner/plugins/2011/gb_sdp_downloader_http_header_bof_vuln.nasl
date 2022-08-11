###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sdp_downloader_http_header_bof_vuln.nasl 11552 2018-09-22 13:45:08Z cfischer $
#
# SDP Downloader HTTP Header Handling Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801834");
  script_version("$Revision: 11552 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 15:45:08 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SDP Downloader HTTP Header Handling Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16078/");
  script_xref(name:"URL", value:"http://securityreason.com/exploitalert/9900");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0253");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_sdp_downloader_detect.nasl");
  script_mandatory_keys("SDP/Downloader/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial
of service or compromise a vulnerable system.");
  script_tag(name:"affected", value:"SDP Downloader version 2.3.0 and prior");
  script_tag(name:"insight", value:"The flaw is caused by a buffer overflow error when processing
overly long HTTP headers, which could be exploited by attackers to crash an
affected application or execute arbitrary code by convincing a user to download a
file from a malicious server.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with SDP Downloader and is prone to
buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

sdpVer = get_kb_item("SDP/Downloader/Ver");
if(!sdpVer){
  exit(0);
}

if(version_is_less_equal(version:sdpVer,test_version:"2.3.0")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
