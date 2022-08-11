###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_formmax_bof_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# FormMax Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900972");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3790");
  script_name("FormMax Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36943");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53890");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_formmax_detect.nasl");
  script_mandatory_keys("FormMax/Evaluation/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue by executing arbitrary code in
the context of an affected application.");
  script_tag(name:"affected", value:"FormMax version 3.5 and prior");
  script_tag(name:"insight", value:"The flaw is due to boundary error while processing malicious
'.aim' import files leading to heap-based buffer overflow.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is installed with FormMax and is prone to Buffer
Overflow Vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

fmVer = get_kb_item("FormMax/Evaluation/Ver");
if(!fmVer){
  exit(0);
}

if(version_is_less_equal(version:fmVer, test_version:"3.5")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
