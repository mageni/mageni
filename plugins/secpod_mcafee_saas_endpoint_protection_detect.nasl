###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mcafee_saas_endpoint_protection_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# McAfee SaaS Endpoint Protection Version Detection (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902561");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("McAfee SaaS Endpoint Protection Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed McAfee SaaS Endpoint Protection
  version and saves the result in KB.");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "McAfee SaaS Endpoint Protection Version Detection (Windows)";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\McAfee\ManagedServices\Agent";
if(!registry_key_exists(key:key)) {
  exit(0);
}

name = registry_get_sz(key:key, item:"szAppName");
if("McAfee Security-as-a-Service" >< name)
{
  version = registry_get_sz(key:key, item:"szMyAsUtilVersion");
  if(version)
  {
    set_kb_item(name:"McAfee/SaaS/Win/Ver", value:version);
    log_message(data:"McAfee SaaS Endpoint Protection " + version +
                       " was detected on the host");

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:mcafee:saas_endpoint_protection:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
