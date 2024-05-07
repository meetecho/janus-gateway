$(document).ready(function() {

	$("div.headertitle").addClass("pb-2 mt-4 mb-2 border-bottom");
	$("div.title").addClass("h1");

	$('li > a[href="index.html"] > span').before("<i class='fa-solid fa-gear'></i> ");
	// $('li > a[href="index.html"] > span').text("CoActionOS");
	$('li > a[href="modules.html"] > span').before("<i class='fa-solid fa-square'></i> ");
	$('li > a[href="namespaces.html"] > span').before("<i class='fa-solid fa-bars'></i> ");
	$('li > a[href="annotated.html"] > span').before("<i class='fa-solid fa-list-ul'></i> ");
	$('li > a[href="classes.html"] > span').before("<i class='fa-solid fa-book'></i> ");
	$('li > a[href="inherits.html"] > span').before("<i class='fa-solid fa-sitemap'></i> ");
	$('li > a[href="functions.html"] > span').before("<i class='fa-solid fa-list'></i> ");
	$('li > a[href="functions_func.html"] > span').before("<i class='fa-solid fa-list'></i> ");
	$('li > a[href="functions_vars.html"] > span').before("<i class='fa-solid fa-list'></i> ");
	$('li > a[href="functions_enum.html"] > span').before("<i class='fa-solid fa-list'></i> ");
	$('li > a[href="functions_eval.html"] > span').before("<i class='fa-solid fa-list'></i> ");
	$('img[src="ftv2ns.png"]').replaceWith('<span class="badge bg-danger">N</span> ');
	$('img[src="ftv2cl.png"]').replaceWith('<span class="badge bg-danger">C</span> ');

	$("ul.tablist").addClass("nav nav-pills nav-fill");
	$("ul.tablist").css("margin-top", "0.5em");
	$("ul.tablist").css("margin-bottom", "0.5em");
	$("ul.tablist > li").addClass("nav-item");
	$("ul.tablist > li > a").addClass("nav-link");
	$("li.current").children().addClass("active");
	$("iframe").attr("scrolling", "yes");

	$("#nav-path > ul").addClass("breadcrumb");

	$("table.params").addClass("table");
	$("div.ingroups").wrapInner("<small></small>");
	$("div.ingroups > small > a").addClass("text-muted");
	$("div.levels").css("margin", "0.5em");
	$("div.levels > span").addClass("btn btn-secondary btn-sm");
	$("div.levels > span").css("margin-right", "0.25em");

	$("table.directory").addClass("table table-striped");
	$("div.summary > a").addClass("btn btn-secondary btn-sm");
	$("table.fieldtable").addClass("table");
	$(".fragment").addClass("card card-body bg-gray");
	$(".memitem").addClass("card");
	$(".memproto").addClass("card-header");
	$(".memdoc").addClass("card-body");
	$("span.mlabel").addClass("badge bg-info");

	$("table.memberdecls").addClass("table");
	$("[class^=memitem]").addClass("active");

	$("div.ah").addClass("btn btn-secondary");
	$("span.mlabels").addClass("pull-right");
	$("table.mlabels").css("width", "100%")
	$("td.mlabels-right").addClass("pull-right");

	$("div.ttc").addClass("card card-info");
	$("div.ttname").addClass("card-header");
	$("div.ttdef,div.ttdoc,div.ttdeci").addClass("card-body");

	$('div.tabs').addClass('container card card-body bg-gray mb-3');
	$('div.tabs2').addClass('container card card-body bg-gray mb-3');
	$('div.tabs3').addClass('container card card-body bg-gray mb-3');
	$('div.header').addClass('container');
	$('div.contents').addClass('container');
	$('div.groupHeader').addClass('alert-link').parent().parent().addClass('alert alert-info');

	$('#MSearchBox').remove();//.parent().appendTo('#topmenu');

	$('code').each(function() { $(this).html($(this).html().replace("–", "--")); } );
});
