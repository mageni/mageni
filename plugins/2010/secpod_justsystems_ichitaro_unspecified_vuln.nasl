###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_justsystems_ichitaro_unspecified_vuln.nasl 14331 2019-03-19 14:03:05Z jschulte $
#
# JustSystems Ichitaro Unspecified Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902042");
  script_version("$Revision: 14331 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:03:05 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_cve_id("CVE-2010-1424");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("JustSystems Ichitaro Unspecified Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39256");
  script_xref(name:"URL", value:"http://www.justsystems.com/jp/info/js10001.html");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0854");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Apr/1023844.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_justsystems_ichitaro_prdts_detect.nasl");
  script_mandatory_keys("Ichitaro/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary commands by
  tricking a user into opening a specially crafted document.");
  script_tag(name:"affected", value:"JustSystems Ichitaro 2006 through 2010");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error when processing font information
  in documents and can be exploited to potentially execute arbitrary code.");
  script_tag(name:"solution", value:"Upgrade to the fixed version.");
  script_tag(name:"summary", value:"This host is installed JustSystems Ichitaro and is prone to
  unspecified vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

ichitaroVer = get_kb_item("Ichitaro/Ver");
if(ichitaroVer)
{
  if(version_in_range(version:ichitaroVer, test_version:"2006", test_version2:"2010")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
