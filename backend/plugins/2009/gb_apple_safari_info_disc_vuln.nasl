###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_info_disc_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Apple Safari RSS Feed Information Disclosure Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800506");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-01-19 13:47:40 +0100 (Mon, 19 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2009-0123");
  script_bugtraq_id(33234);
  script_name("Apple Safari RSS Feed Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/366491.php");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47917");
  script_xref(name:"URL", value:"http://brian.mastenbrook.net/display/27");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful remote exploitation can potentially be exploited to gain access
  to sensitive information and launch other attacks.");
  script_tag(name:"affected", value:"Apple Safari 3.1.2 and prior on Windows.");
  script_tag(name:"insight", value:"Flaw is due an error generated in safari web browser while handling feed,
  feeds and feedsearch URL types for RSS feeds.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Apple Safari web browser which is prone
  to remote file access vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

if(version_is_less_equal(version:safVer, test_version:"3.525.21.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
