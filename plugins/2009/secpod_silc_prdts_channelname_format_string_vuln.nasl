###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_silc_prdts_channelname_format_string_vuln.nasl 14335 2019-03-19 14:46:57Z asteins $
#
# SILC Client & Toolkit Channel Name Format String Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900958");
  script_version("$Revision: 14335 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:46:57 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3163");
  script_bugtraq_id(36193);
  script_name("SILC Client Channel Name Format String Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36134");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/09/03/5");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_silc_prdts_detect.nasl");
  script_mandatory_keys("SILC/Client/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this iisue to execute arbitrary code in the
  context of the affected application and compromise the system.");
  script_tag(name:"affected", value:"SILC Client 1.1.8 and prior
  SILC Toolkit prior to 1.1.10.");
  script_tag(name:"insight", value:"Multiple format string errors occur in 'lib/silcclient/command.c' while
  processing format string specifiers in the channel name field.");
  script_tag(name:"summary", value:"This host has SILC Client installed and is prone to Format
  String vulnerability.");
  script_tag(name:"solution", value:"Apply the patch or upgrade to SILC Toolkit 1.1.10.  *****
  NOTE: Please ignore this warning if the patch is already applied.
  *****");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://silcnet.org/");
  exit(0);
}


include("version_func.inc");

clntVer = get_kb_item("SILC/Client/Ver");
if(clntVer)
{
  if(version_is_less_equal(version:clntVer, test_version:"1.1.8"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
