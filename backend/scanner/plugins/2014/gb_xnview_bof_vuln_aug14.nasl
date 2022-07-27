###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xnview_bof_vuln_aug14.nasl 11878 2018-10-12 12:40:08Z cfischer $
#
# XnView JPEG-LS Image Processing Buffer Overflow Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:xnview:xnview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804822");
  script_version("$Revision: 11878 $");
  script_cve_id("CVE-2012-4988");
  script_bugtraq_id(55787);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-08-26 10:14:25 +0530 (Tue, 26 Aug 2014)");
  script_name("XnView JPEG-LS Image Processing Buffer Overflow Vulnerability");


  script_tag(name:"summary", value:"This host is installed with XnView and is prone to buffer overflow
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists due to improper bounds checking when processing JPEG-LS
(lossless compression) images.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to potentially execute
arbitrary code on the target machine.");
  script_tag(name:"affected", value:"XnView versions 1.99 and 1.99.1");
  script_tag(name:"solution", value:"Update to XnView version 1.99.6 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50825");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027607");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79030");
  script_xref(name:"URL", value:"http://www.reactionpenetrationtesting.co.uk/xnview-jls-heap.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");
  script_xref(name:"URL", value:"http://www.xnview.com/en");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:version, test_version:"1.99") ||
   version_is_equal(version:version, test_version:"1.99.1"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
