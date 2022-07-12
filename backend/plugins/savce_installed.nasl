###############################################################################
# OpenVAS Vulnerability Test
# $Id: savce_installed.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# Symantec Anti Virus Corporate Edition Check
#
# Authors:
# Rewritten by Montgomery County
# Original script was written by Jeff Adams <jeffadams@comcast.net>
# and Tenable Network Security
# Modified by Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2004-2005 Jeff Adams / Tenable Network Security
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.80040");
  script_version("$Revision: 12413 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Symantec Anti Virus Corporate Edition Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004-2005 Jeff Adams / Tenable Network Security");
  script_family("Product detection");
  script_dependencies("smb_enum_services.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"solution", value:"Make sure SAVCE is installed, running and using the latest
  VDEFS.");

  script_tag(name:"summary", value:"This plugin checks that the remote host has Symantec AntiVirus
  Corporate installed and properly running, and makes sure that the latest Vdefs are loaded.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

##This NVT is deprecated as it produces false positives.
## Moreover it is not referenced by any of the NVTs.
exit(66);

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Symantec Anti Virus Corporate Edition Check";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

global_var soft_path;

#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#
function check_signature_version ()
{
  local_var key, item, items, key_h, val, value, path, vers;

  key = soft_path + "Symantec\InstalledApps\";

   if(!registry_key_exists(key:key)){
      return NULL;
   }

   value = registry_get_sz(item:"AVENGEDEFS", key:key);
   if (value) path = value;
   if (isnull(path)) return NULL;

   key = soft_path + "Symantec\SharedDefs\";

   if(!registry_key_exists(key:key)){
    return 0;
   }

   items = make_list(
      "DEFWATCH_10",
      "NAVCORP_72",
      "NAVCORP_70",
      "NAVNT_50_AP1"
    );

    foreach item (items)
    {
      value = registry_get_sz(item:item, key:key);
      if(!value || isnull (value) )continue;

        val = value;
        if (stridx(val, path) == 0)
        {
          val = val - (path+"\");
          if ("." >< val) val = val - strstr(val, ".");
          if (isnull(vers) || int(vers) < int(val)) vers = val;
        }

    }

  if (!vers) return NULL;

  set_kb_item(name: "Antivirus/SAVCE/signature", value:vers);
  return vers;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
# Note that major version will only be reported (ie. 9.0.1000 #
#    instead of 9.0.5.1000)                                   #
# Also you can check ProductVersion in                        #
#    HKLM\SOFTWARE\INTEL\LANDesk\VirusProtect6\CurrentVersion #
#-------------------------------------------------------------#

function check_product_version ()
{
  local_var key, item, key_h, value, directory, output, version, vhigh, vlow, v1, v2, v3;

  key = soft_path + "INTEL\LANDesk\VirusProtect6\CurrentVersion";
  item = "ProductVersion";

  if(!registry_key_exists(key:key)){
    key = soft_path + "Symantec\Symantec Endpoint Protection\AV";
  }

  if(!registry_key_exists(key:key)){
    return 0;
  }

   version = registry_get_sz(item:item, key:key);

   if (version)
   {
    vhigh = version & 0xFFFF;
    vlow = (version >>> 16);

    v1 = vhigh / 100;
    v2 = (vhigh%100)/10;
    v3 = (vhigh%10);

    if ( (v1 / 10) > 1 )
    {
      v3 = (v1 / 10 - 1) * 1000;
      v1 = 10 + v1 % 10;
    }

    version = string (v1, ".", v2, ".", v3, ".", vlow);

    set_kb_item(name: "Antivirus/SAVCE/version", value:version);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:symantec:norton_antivirus:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    return version;
   }

 return NULL;
}

#-------------------------------------------------------------#
# Checks if Symantec AntiVirus Corp is installed              #
#-------------------------------------------------------------#

key = "SOFTWARE\Wow6432Node\Symantec\InstalledApps\";
item = "SAVCE";

if(registry_key_exists(key:key)){
  soft_path = "SOFTWARE\Wow6432Node\";
}

if (!soft_path)
{
 key = "SOFTWARE\Symantec\InstalledApps\";
 if(registry_key_exists(key:key)){
   soft_path = "SOFTWARE\";
 }
}

if (soft_path)
{
 value = registry_get_sz(item:item, key:key);
}
else
{
  exit(0);
}

if (!value)
{
  exit(0);
}

set_kb_item(name: "Antivirus/SAVCE/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#

# Take the first signature version key
current_signature_version = check_signature_version ();

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

services = get_kb_item("SMB/svcs");

# Thanks to Jeff Adams for Symantec service.
if ( services )
{
  if (("Norton AntiVirus" >!< services) && (!egrep(pattern:"\[ *Symantec AntiVirus *\]", string:services, icase:TRUE)))
    running = 0;
  else
    running = 1;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
product_version = check_product_version();


#-------------------------------------------------------------#
# Checks if Symantec AntiVirus Corp has Parent server set     #
#-------------------------------------------------------------#

key = soft_path + "Intel\LANDesk\VirusProtect6\CurrentVersion\";
item = "Parent";

if (registry_key_exists(key:key))
{
 parent = registry_get_sz(item:item, key:key);
}

if ( strlen(parent)<=1 )
{
  set_kb_item(name: "Antivirus/SAVCE/noparent", value:TRUE);
}
else
{
  set_kb_item(name: "Antivirus/SAVCE/parent", value:parent);
}

# var initialization
warning = 0;

#
# We first report information about the antivirus
#
report = "
The remote host has the Symantec Antivirus Corporate installed. It has
been fingerprinted as :

";

report += "Symantec Antivirus Corporate " + product_version + "
DAT version : " + current_signature_version + "

";

#
# Check if antivirus signature is up-to-date
#

# Last Database Version
virus = "20080923";
if(current_signature_version>0) {
  if ( int(current_signature_version) < ( int(virus) - 1 ) )
  {
    report += "The remote host has an out-dated version of the Symantec
Corporate virus signatures. Last version is " + virus + "

  ";
    warning = 1;
  }
}

#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote Symantec AntiVirus Corporate is not running.

";
  set_kb_item(name: "Antivirus/SAVCE/running", value:FALSE);
  warning = 1;
}
else
{
  set_kb_item(name: "Antivirus/SAVCE/running", value:TRUE);
}

#
# Create the final report
#

if (warning)
{
  report += "As a result, the remote host might be infected by viruses received by
email or other means.";

  log_message(port:0, data:report);
}
else
{
  set_kb_item (name:"Antivirus/SAVCE/description", value:report);
}

exit(0);
