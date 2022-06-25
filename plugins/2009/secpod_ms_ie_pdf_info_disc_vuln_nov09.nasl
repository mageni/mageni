###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_pdf_info_disc_vuln_nov09.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Microsoft Internet Explorer PDF Information Disclosure Vulnerability - Nov09
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
  script_oid("1.3.6.1.4.1.25623.1.0.900897");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-4073");
  script_bugtraq_id(37117);
  script_name("Microsoft Internet Explorer PDF Information Disclosure Vulnerability - Nov09");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37362/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/508010/100/0/threaded");
  script_xref(name:"URL", value:"http://www.theregister.co.uk/2009/11/23/internet_explorer_file_disclosure_bug/");
  script_xref(name:"URL", value:"http://securethoughts.com/2009/11/millions-of-pdf-invisibly-embedded-with-your-internal-disk-paths/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name:"impact", value:"Successful attacks which may leads to the exposure of system
information on the affected system.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6/7/8 on Windows.");
  script_tag(name:"insight", value:"The weakness is due to an Internet Explorer including the first
63 bytes of the file path in the 'Title' property when converting local HTML or
MHT files to PDF using a PDF printer. This can lead to the exposure of certain
system information e.g. the user name.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Internet Explorer and is prone to
Information Disclosure vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(ieVer =~ "^(6|7|8)\..*"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
