import{p as at}from"./chunk-JWPE2WC7-C9Kkp5Jc.js";import{a2 as T,a5 as B,b5 as nt,g as rt,s as it,a as ot,b as st,o as lt,n as ct,_ as d,l as G,c as ut,A as gt,D as dt,K as pt,e as ht,p as ft,B as mt}from"./mermaid.core-Bx4wpDMx.js";import{p as vt}from"./cynefin-VYW2F7L2-pP9QSLOf.js";import{d as Z}from"./arc-DN8Ua-P6.js";import{o as xt}from"./ordinal-Cboi1Yqb.js";import"./index-CALoiqKI.js";import"./init-Gi6I4Gst.js";function yt(t,r){return r<t?-1:r>t?1:r>=t?0:NaN}function St(t){return t}function wt(){var t=St,r=yt,S=null,b=T(0),l=T(B),p=T(0);function i(e){var n,s=(e=nt(e)).length,h,w,D=0,f=new Array(s),o=new Array(s),A=+b.apply(this,arguments),E=Math.min(B,Math.max(-B,l.apply(this,arguments)-A)),k,L=Math.min(Math.abs(E)/s,p.apply(this,arguments)),u=L*(E<0?-1:1),C;for(n=0;n<s;++n)(C=o[f[n]=n]=+t(e[n],n,e))>0&&(D+=C);for(r!=null?f.sort(function(M,m){return r(o[M],o[m])}):S!=null&&f.sort(function(M,m){return S(e[M],e[m])}),n=0,w=D?(E-s*u)/D:0;n<s;++n,A=k)h=f[n],C=o[h],k=A+(C>0?C*w:0)+u,o[h]={data:e[h],index:n,value:C,startAngle:A,endAngle:k,padAngle:L};return o}return i.value=function(e){return arguments.length?(t=typeof e=="function"?e:T(+e),i):t},i.sortValues=function(e){return arguments.length?(r=e,S=null,i):r},i.sort=function(e){return arguments.length?(S=e,r=null,i):S},i.startAngle=function(e){return arguments.length?(b=typeof e=="function"?e:T(+e),i):b},i.endAngle=function(e){return arguments.length?(l=typeof e=="function"?e:T(+e),i):l},i.padAngle=function(e){return arguments.length?(p=typeof e=="function"?e:T(+e),i):p},i}var At=mt.pie,I={sections:new Map,showData:!1},H=I.sections,V=I.showData,Ct=structuredClone(At),$t=d(()=>structuredClone(Ct),"getConfig"),Dt=d(()=>{H=new Map,V=I.showData,ft()},"clear"),Tt=d(({label:t,value:r})=>{if(r<0)throw new Error(`"${t}" has invalid value: ${r}. Negative values are not allowed in pie charts. All slice values must be >= 0.`);H.has(t)||(H.set(t,r),G.debug(`added new section: ${t}, with value: ${r}`))},"addSection"),bt=d(()=>H,"getSections"),kt=d(t=>{V=t},"setShowData"),zt=d(()=>V,"getShowData"),q={getConfig:$t,clear:Dt,setDiagramTitle:ct,getDiagramTitle:lt,setAccTitle:st,getAccTitle:ot,setAccDescription:it,getAccDescription:rt,addSection:Tt,getSections:bt,setShowData:kt,getShowData:zt},Et=d((t,r)=>{at(t,r),r.setShowData(t.showData),t.sections.map(r.addSection)},"populateDb"),Mt={parse:d(async t=>{const r=await vt("pie",t);G.debug(r),Et(r,q)},"parse")},Rt=d(t=>`
  .pieCircle{
    stroke: ${t.pieStrokeColor};
    stroke-width : ${t.pieStrokeWidth};
    opacity : ${t.pieOpacity};
  }
  .pieCircle.highlighted{
    scale: 1.05;
    opacity: 1;
  }
  .pieCircle.highlightedOnHover:hover{
    transition-duration: 250ms;
    scale: 1.05;
    opacity: 1;
  }
  .pieOuterCircle{
    stroke: ${t.pieOuterStrokeColor};
    stroke-width: ${t.pieOuterStrokeWidth};
    fill: none;
  }
  .pieTitleText {
    text-anchor: middle;
    font-size: ${t.pieTitleTextSize};
    fill: ${t.pieTitleTextColor};
    font-family: ${t.fontFamily};
  }
  .slice {
    font-family: ${t.fontFamily};
    fill: ${t.pieSectionTextColor};
    font-size:${t.pieSectionTextSize};
    // fill: white;
  }
  .legend text {
    fill: ${t.pieLegendTextColor};
    font-family: ${t.fontFamily};
    font-size: ${t.pieLegendTextSize};
  }
`,"getStyles"),Lt=Rt,_t=d(t=>{const r=[...t.values()].reduce((l,p)=>l+p,0),S=[...t.entries()].map(([l,p])=>({label:l,value:p})).filter(l=>l.value/r*100>=1);return wt().value(l=>l.value).sort(null)(S)},"createPieArcs"),Ft=d((t,r,S,b)=>{G.debug(`rendering pie chart
`+t);const l=b.db,p=ut(),i=gt(l.getConfig(),p.pie),e=40,n=18,s=4,h=450,w=h,D=dt(r),f=D.append("g");f.attr("transform","translate("+w/2+","+h/2+")");const{themeVariables:o}=p;let[A]=pt(o.pieOuterStrokeWidth);A??(A=2);const E=i.legendPosition,k=i.textPosition,L=i.donutHole>0&&i.donutHole<=.9?i.donutHole:0,u=Math.min(w,h)/2-e,C=Z().innerRadius(L*u).outerRadius(u),M=Z().innerRadius(u*k).outerRadius(u*k),m=f.append("g");m.append("circle").attr("cx",0).attr("cy",0).attr("r",u+A/2).attr("class","pieOuterCircle");const _=l.getSections(),J=_t(_),Q=[o.pie1,o.pie2,o.pie3,o.pie4,o.pie5,o.pie6,o.pie7,o.pie8,o.pie9,o.pie10,o.pie11,o.pie12];let N=0;_.forEach(a=>{N+=a});const U=J.filter(a=>(a.data.value/N*100).toFixed(0)!=="0"),O=xt(Q).domain([..._.keys()]);m.selectAll("mySlices").data(U).enter().append("path").attr("d",C).attr("fill",a=>O(a.data.label)).attr("class",a=>{let c="pieCircle";return i.highlightSlice==="hover"?c+=" highlightedOnHover":i.highlightSlice===a.data.label&&(c+=" highlighted"),c}),m.selectAll("mySlices").data(U).enter().append("text").text(a=>(a.data.value/N*100).toFixed(0)+"%").attr("transform",a=>"translate("+M.centroid(a)+")").style("text-anchor","middle").attr("class","slice");const Y=f.append("text").text(l.getDiagramTitle()).attr("x",0).attr("y",-400/2).attr("class","pieTitleText"),R=[..._.entries()].map(([a,c])=>({label:a,value:c})),$=f.selectAll(".legend").data(R).enter().append("g").attr("class","legend");$.append("rect").attr("width",n).attr("height",n).style("fill",a=>O(a.label)).style("stroke",a=>O(a.label)),$.append("text").attr("x",n+s).attr("y",n-s).text(a=>l.getShowData()?`${a.label} [${a.value}]`:a.label);const z=Math.max(...$.selectAll("text").nodes().map(a=>a?.getBoundingClientRect().width??0));let F=h,P=w+e;const g=n+s,W=R.length*g;switch(E){case"center":$.attr("transform",(a,c)=>{const v=g*R.length/2,x=-z/2-(n+s),y=c*g-v;return"translate("+x+","+y+")"});break;case"top":F+=W,$.attr("transform",(a,c)=>{const v=u,x=-z/2-(n+s),y=c*g-v;return`translate(${x}, ${y})`}),m.attr("transform",()=>`translate(0, ${W+g})`);break;case"bottom":F+=W,$.attr("transform",(a,c)=>{const v=-u-g,x=-z/2-(n+s),y=c*g-v;return"translate("+x+","+y+")"});break;case"left":P+=n+s+z,$.attr("transform",(a,c)=>{const v=g*R.length/2,x=-u-(n+s),y=c*g-v;return"translate("+x+","+y+")"}),m.attr("transform",()=>`translate(${z+n+s}, 0)`);break;default:P+=n+s+z,$.attr("transform",(a,c)=>{const v=g*R.length/2,x=12*n,y=c*g-v;return"translate("+x+","+y+")"});break}const j=Y.node()?.getBoundingClientRect().width??0,tt=w/2-j/2,et=w/2+j/2,K=Math.min(0,tt),X=Math.max(P,et)-K;D.attr("viewBox",`${K} 0 ${X} ${F}`),ht(D,F,X,i.useMaxWidth)},"draw"),Ht={draw:Ft},Ut={parser:Mt,db:q,renderer:Ht,styles:Lt};export{Ut as diagram};
