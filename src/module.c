#include "module.h"

#include "cli.h"

#include <stdio.h>

typedef struct {
	CmdId id;
	const char *function;
	const char *target;
	const char *param_help;
	const char *example;
} CmdletMap;

static const CmdletMap cmdlets[] = {
    {CMD_GET, "Get-EnvctlValue", NULL,
     "\t.PARAMETER Key\n\tThe key to read.\n"
     "\t.PARAMETER File\n\tThe env file; ./.env when omitted.\n"
     "\t.PARAMETER Environment\n\tRead the process environment instead of a file.\n",
     "Get-EnvctlValue -Key DATABASE_URL -File .env"},
    {CMD_SET, "Set-EnvctlValue", "set $Key",
     "\t.PARAMETER Key\n\tThe key to set or replace.\n"
     "\t.PARAMETER Value\n\tThe literal value; empty when omitted.\n"
     "\t.PARAMETER File\n\tThe env file; ./.env when omitted.\n",
     "Set-EnvctlValue -Key DEBUG -Value true -WhatIf"},
    {CMD_DISABLE, "Disable-EnvctlKey", "disable $Key",
     "\t.PARAMETER Key\n\tThe key to comment out.\n"
     "\t.PARAMETER File\n\tThe env file; ./.env when omitted.\n",
     "Disable-EnvctlKey -Key DEBUG"},
    {CMD_ENABLE, "Enable-EnvctlKey", "enable $Key",
     "\t.PARAMETER Key\n\tThe key to uncomment.\n"
     "\t.PARAMETER File\n\tThe env file; ./.env when omitted.\n",
     "Enable-EnvctlKey -Key DEBUG"},
    {CMD_DELETE, "Remove-EnvctlKey", "delete $Key",
     "\t.PARAMETER Key\n\tThe key to remove, active and commented.\n"
     "\t.PARAMETER File\n\tThe env file; ./.env when omitted.\n",
     "Remove-EnvctlKey -Key DEBUG -WhatIf"},
    {CMD_LIST, "Get-EnvctlKey", NULL,
     "\t.PARAMETER File\n\tThe env file; ./.env when omitted.\n"
     "\t.PARAMETER Environment\n\tRead the process environment instead of a file.\n",
     "Get-EnvctlKey -File .env | Where-Object Disabled"},
    {CMD_ENV, "Get-EnvctlEnvironment", NULL, "", "Get-EnvctlEnvironment | Where-Object Redacted"},
    {CMD_REDACT, "Invoke-EnvctlRedact", NULL,
     "\t.PARAMETER InputObject\n\tLines to filter; accepts pipeline input.\n"
     "\t.PARAMETER File\n\tThe env file supplying literal values; ./.env when omitted.\n"
     "\t.PARAMETER Environment\n\tMask the process environment's literal values.\n"
     "\t.PARAMETER NoEnv\n\tSkip literal values, use heuristics only.\n",
     "npm run build 2>&1 | Invoke-EnvctlRedact -Environment"},
};
#define CMDLET_COUNT ((int)(sizeof cmdlets / sizeof *cmdlets))

static const FlagId pass_flags[] = {FLAG_SORT, FLAG_REDACT, FLAG_RAW, FLAG_PARANOID};
#define PASS_FLAG_COUNT ((int)(sizeof pass_flags / sizeof *pass_flags))

static const char *pass_flag_params[] = {"Sort", "Redact", "Raw", "Paranoid"};

static const Command *command_of(CmdId id) {
	for (int i = 0; i < CMD_COUNT; i++) {
		if (cli_commands[i].id == id)
			return &cli_commands[i];
	}
	return NULL;
}

static void put_help(const Command *c, const CmdletMap *m) {
	printf("\t<#\n\t.SYNOPSIS\n\t%s, through envctl %s.\n", c->summary, c->name);
	printf("\t.DESCRIPTION\n\t%s\n", c->description);
	fputs(m->param_help, stdout);
	for (int i = 0; i < PASS_FLAG_COUNT; i++) {
		if (cli_flags[pass_flags[i]].commands & CMD_BIT(c->id))
			printf("\t.PARAMETER %s\n\tPass %s: %s.\n", pass_flag_params[i],
			       cli_flags[pass_flags[i]].name, cli_flags[pass_flags[i]].summary);
	}
	printf("\t.EXAMPLE\n\t%s\n\t#>\n", m->example);
}

static void put_pass_params(const Command *c) {
	for (int i = 0; i < PASS_FLAG_COUNT; i++) {
		if (cli_flags[pass_flags[i]].commands & CMD_BIT(c->id))
			printf(",\n\t\t[switch]$%s", pass_flag_params[i]);
	}
}

static void put_pass_args(const Command *c) {
	for (int i = 0; i < PASS_FLAG_COUNT; i++) {
		if (cli_flags[pass_flags[i]].commands & CMD_BIT(c->id))
			printf("\tif ($%s) { $a += '%s' }\n", pass_flag_params[i],
			       cli_flags[pass_flags[i]].name);
	}
}

static void put_invoke_checked(const char *what) {
	printf("\t$out = & envctl @a\n"
	       "\tif ($LASTEXITCODE) {\n"
	       "\t\tWrite-Error \"envctl %s failed with exit code $LASTEXITCODE\"\n"
	       "\t\treturn\n"
	       "\t}\n",
	       what);
}

static void put_kv_objects(int listish) {
	if (listish)
		fputs("\t$src = if ($Environment) { $null } elseif ($File) { $File } else { '.env' }\n",
		      stdout);
	fputs("\tforeach ($line in @($out)) {\n", stdout);
	if (listish)
		fputs("\t\t$off = $false\n"
		      "\t\tif ($line.EndsWith(' (disabled)')) {\n"
		      "\t\t\t$off = $true\n"
		      "\t\t\t$line = $line.Substring(0, $line.Length - 11)\n"
		      "\t\t}\n",
		      stdout);
	fputs("\t\t$i = $line.IndexOf('=')\n"
	      "\t\tif ($i -lt 0) { continue }\n"
	      "\t\t$v = $line.Substring($i + 1)\n"
	      "\t\t$kind = $null\n"
	      "\t\t$red = $v -match '^<redacted(:(?<kind>[a-z-]+))?>$'\n"
	      "\t\tif ($red) { $kind = $Matches['kind'] }\n",
	      stdout);
	if (listish)
		fputs("\t\t[pscustomobject]@{\n"
		      "\t\t\tKey           = $line.Substring(0, $i)\n"
		      "\t\t\tValue         = $v\n"
		      "\t\t\tRedacted      = $red\n"
		      "\t\t\tRedactionKind = $kind\n"
		      "\t\t\tDisabled      = $off\n"
		      "\t\t\tFile          = $src\n"
		      "\t\t}\n",
		      stdout);
	else
		fputs("\t\t[pscustomobject]@{\n"
		      "\t\t\tKey           = $line.Substring(0, $i)\n"
		      "\t\t\tValue         = $v\n"
		      "\t\t\tRedacted      = $red\n"
		      "\t\t\tRedactionKind = $kind\n"
		      "\t\t}\n",
		      stdout);
	fputs("\t}\n", stdout);
}

static void put_get(const Command *c, const CmdletMap *m) {
	printf("function %s {\n", m->function);
	put_help(c, m);
	fputs("\t[CmdletBinding()]\n"
	      "\tparam(\n"
	      "\t\t[Parameter(Mandatory, Position = 0)][string]$Key,\n"
	      "\t\t[string]$File,\n"
	      "\t\t[switch]$Environment",
	      stdout);
	put_pass_params(c);
	fputs("\n\t)\n"
	      "\t$a = @('get')\n"
	      "\tif ($Environment) { $a += '--env' }\n"
	      "\telseif ($File) { $a += $File }\n"
	      "\t$a += $Key\n",
	      stdout);
	put_pass_args(c);
	fputs("\t$out = & envctl @a\n"
	      "\tif ($LASTEXITCODE) {\n"
	      "\t\tWrite-Error \"$Key is unset (envctl get exit code $LASTEXITCODE)\"\n"
	      "\t\treturn\n"
	      "\t}\n"
	      "\t$out\n"
	      "}\n\n",
	      stdout);
}

static void put_mutating(const Command *c, const CmdletMap *m, int has_value) {
	printf("function %s {\n", m->function);
	put_help(c, m);
	fputs("\t[CmdletBinding(SupportsShouldProcess)]\n"
	      "\tparam(\n"
	      "\t\t[Parameter(Mandatory, Position = 0)][string]$Key,\n",
	      stdout);
	if (has_value)
		fputs("\t\t[Parameter(Position = 1)][AllowEmptyString()][string]$Value = '',\n", stdout);
	fputs("\t\t[string]$File", stdout);
	put_pass_params(c);
	fputs("\n\t)\n", stdout);
	printf("\t$a = @('%s')\n", c->name);
	fputs("\tif ($File) { $a += $File }\n\t$a += $Key\n", stdout);
	if (has_value)
		fputs("\t$a += $Value\n", stdout);
	put_pass_args(c);
	printf(
	    "\tif (-not $PSCmdlet.ShouldProcess($(if ($File) { $File } else { '.env' }), \"%s\")) {\n"
	    "\t\t& envctl @(@('--dry-run') + $a)\n"
	    "\t\treturn\n"
	    "\t}\n",
	    m->target);
	put_invoke_checked(c->name);
	fputs("\t$out\n}\n\n", stdout);
}

static void put_list(const Command *c, const CmdletMap *m) {
	printf("function %s {\n", m->function);
	put_help(c, m);
	fputs("\t[CmdletBinding()]\n"
	      "\tparam(\n"
	      "\t\t[string]$File,\n"
	      "\t\t[switch]$Environment",
	      stdout);
	put_pass_params(c);
	fputs("\n\t)\n"
	      "\t$a = @('list', '--values')\n"
	      "\tif ($Environment) { $a += '--env' }\n"
	      "\telse {\n"
	      "\t\t$a += '--all'\n"
	      "\t\tif ($File) { $a += $File }\n"
	      "\t}\n",
	      stdout);
	put_pass_args(c);
	put_invoke_checked("list");
	put_kv_objects(1);
	fputs("}\n\n", stdout);
}

static void put_env(const Command *c, const CmdletMap *m) {
	printf("function %s {\n", m->function);
	put_help(c, m);
	fputs("\t[CmdletBinding()]\n"
	      "\tparam(",
	      stdout);
	int first = 1;
	for (int i = 0; i < PASS_FLAG_COUNT; i++) {
		if (!(cli_flags[pass_flags[i]].commands & CMD_BIT(c->id)))
			continue;
		printf("%s\n\t\t[switch]$%s", first ? "" : ",", pass_flag_params[i]);
		first = 0;
	}
	fputs("\n\t)\n"
	      "\t$a = @('env')\n",
	      stdout);
	put_pass_args(c);
	put_invoke_checked("env");
	fputs("\t$out = @($out) | Where-Object { -not $_.StartsWith('# ') }\n", stdout);
	put_kv_objects(0);
	fputs("}\n\n", stdout);
}

static void put_redact(const Command *c, const CmdletMap *m) {
	printf("function %s {\n", m->function);
	put_help(c, m);
	fputs("\t[CmdletBinding()]\n"
	      "\tparam(\n"
	      "\t\t[Parameter(ValueFromPipeline)][string[]]$InputObject,\n"
	      "\t\t[string]$File,\n"
	      "\t\t[switch]$Environment,\n"
	      "\t\t[switch]$NoEnv",
	      stdout);
	put_pass_params(c);
	fputs("\n\t)\n"
	      "\tbegin { $lines = [System.Collections.Generic.List[string]]::new() }\n"
	      "\tprocess { foreach ($l in $InputObject) { $lines.Add([string]$l) } }\n"
	      "\tend {\n"
	      "\t\t$a = @('redact')\n"
	      "\t\tif ($Environment) { $a += '--env' }\n"
	      "\t\telseif ($NoEnv) { $a += '--no-env' }\n"
	      "\t\telseif ($File) { $a += $File }\n",
	      stdout);
	for (int i = 0; i < PASS_FLAG_COUNT; i++) {
		if (cli_flags[pass_flags[i]].commands & CMD_BIT(c->id))
			printf("\t\tif ($%s) { $a += '%s' }\n", pass_flag_params[i],
			       cli_flags[pass_flags[i]].name);
	}
	fputs("\t\t$lines | & envctl @a\n"
	      "\t\tif ($LASTEXITCODE) {\n"
	      "\t\t\tWrite-Error \"envctl redact failed with exit code $LASTEXITCODE\"\n"
	      "\t\t}\n"
	      "\t}\n"
	      "}\n\n",
	      stdout);
}

void act_module_pwsh(void) {
	fputs("Set-StrictMode -Version 3.0\n\n", stdout);
	for (int i = 0; i < CMDLET_COUNT; i++) {
		const Command *c = command_of(cmdlets[i].id);
		switch (cmdlets[i].id) {
		case CMD_GET:
			put_get(c, &cmdlets[i]);
			break;
		case CMD_SET:
			put_mutating(c, &cmdlets[i], 1);
			break;
		case CMD_DISABLE:
		case CMD_ENABLE:
		case CMD_DELETE:
			put_mutating(c, &cmdlets[i], 0);
			break;
		case CMD_LIST:
			put_list(c, &cmdlets[i]);
			break;
		case CMD_ENV:
			put_env(c, &cmdlets[i]);
			break;
		case CMD_REDACT:
			put_redact(c, &cmdlets[i]);
			break;
		default:
			break;
		}
	}
}
