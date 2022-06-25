###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_designworks_professional_bof_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# DesignWorks Professional '.cct' File BOF Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800368");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-03-18 05:31:55 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6363");
  script_bugtraq_id(32667);
  script_name("DesignWorks Professional '.cct' File BOF Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33043");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7362");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/3369");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_designworks_professional_detect.nasl");
  script_mandatory_keys("DesignWorks/Prof/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers execute arbitrary code
  by tricking a user into opening a specially crafted file and can cause stack
  overflow in the context of the affected application.");
  script_tag(name:"affected", value:"DesignWorks Professional version 5.0.7 and prior.");
  script_tag(name:"insight", value:"Boundary error exists when processing '.cct' files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is installed with DesignWorks Professional and is prone
  to stack overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

dwpVer = get_kb_item("DesignWorks/Prof/Ver");
if(!dwpVer){
  exit(0);
}

if(version_is_less_equal(version:dwpVer, test_version:"5.0.7")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
