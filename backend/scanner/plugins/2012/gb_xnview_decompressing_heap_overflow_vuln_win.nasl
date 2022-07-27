###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xnview_decompressing_heap_overflow_vuln_win.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# XnView Multiple Image Decompression Heap Overflow Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802444");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2012-0276", "CVE-2012-0277", "CVE-2012-0282");
  script_bugtraq_id(54125);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-24 15:21:56 +0530 (Tue, 24 Jul 2012)");
  script_name("XnView Multiple Image Decompression Heap Overflow Vulnerabilities (Windows)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code on the
  system or cause a denial of service condition.");
  script_tag(name:"affected", value:"XnView versions prior to 1.99 on windows");
  script_tag(name:"solution", value:"Update to XnView version 1.99 or later.");
  script_tag(name:"summary", value:"This host has XnView installed and is prone to multiple heap
  based buffer overflow vulnerabilities.

  Vulnerabilities Insight:

  - Insufficient validation when decompressing SGI32LogLum compressed
    TIFF images.

  - Insufficient validation when decompressing SGI32LogLum compressed TIFF
    images where the PhotometricInterpretation encoding is set to LogL.

  - Insufficient validation when decompressing PCT images.

  - An indexing error when processing the ImageDescriptor structure of GIF
    images.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48666");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19336/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19337/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19338/");
  script_xref(name:"URL", value:"http://newsgroup.xnview.com/viewtopic.php?f=35&t=25858");
  script_xref(name:"URL", value:"http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=48");
  script_xref(name:"URL", value:"http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=49");
  script_xref(name:"URL", value:"http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=50");
  script_xref(name:"URL", value:"http://www.xnview.com/");
  exit(0);
}


include("version_func.inc");

xnviewVer = get_kb_item("XnView/Win/Ver");
if(isnull(xnviewVer)){
  exit(0);
}

if(version_is_less(version:xnviewVer, test_version:"1.99")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
