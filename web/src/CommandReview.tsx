// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ActionTemplate } from "./api";

export function CommandReview({template,expectedVersion,language}:{template?:ActionTemplate;expectedVersion:number|null;language:"zh-CN"|"en"}) {
  if(!template?.command)return null;
  const zh=language==="zh-CN";
  if(template.version!==expectedVersion)return <p className="mt-3 text-sm text-amber-800">{zh?"模板已修改，这条审批不能用于当前配置；请重新申请。":"The template changed; request a new approval for the current configuration."}</p>;
  const config=template.command;
  return <details className="mt-3 border-y border-slate-200 py-3"><summary className="cursor-pointer text-sm font-semibold text-cyan-800">{zh?"查看将执行的程序与插槽":"Review program and credential slots"}</summary><dl className="mt-3 grid gap-2 text-xs sm:grid-cols-[6rem_1fr]">
    <dt className="text-slate-500">{zh?"程序":"Program"}</dt><dd className="m-0 break-all font-mono">{config.program}</dd>
    <dt className="text-slate-500">{zh?"工作目录":"Directory"}</dt><dd className="m-0 break-all font-mono">{config.working_directory}</dd>
    <dt className="text-slate-500">{zh?"参数":"Arguments"}</dt><dd className="m-0 whitespace-pre-wrap break-all font-mono">{JSON.stringify(config.arguments,null,2)}</dd>
    <dt className="text-slate-500">{zh?"凭据插槽":"Slots"}</dt><dd className="m-0 space-y-1">{config.slots.map(slot=><p key={slot.name} className="m-0">{slot.name} → {slot.injection}{slot.environment_variable?` (${slot.environment_variable})`:""}</p>)}</dd>
  </dl></details>;
}
