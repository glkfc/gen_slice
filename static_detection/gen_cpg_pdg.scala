import scala.io.{BufferedSource, Source}

/*
...
*/

importCode("../data/test_c/a.c", "a")

val cpg_json_path = "../data/joern_data/cpg_json.json"
val pdg_txt_path = "../data/joern_data/pdg_txt.txt"

cpg.all.toJsonPretty #> cpg_json_path


//cpg.method.name("func").dotPdg.l

// ...
val userDefinedMethods = cpg.method
  .nameNot("<global>")
  .nameNot("<operator>.*")
  .nameNot(".*::.*")
  .filter(_.isExternal == false)

for(function <- userDefinedMethods ){
    function.dotPdg #>> pdg_txt_path
}


/*
...
*/

val json_path = "../data/joern_data/scan_api.txt"
val method_chain_path = "../data/joern_data/method_chain.json"
val method_call_path = "../data/joern_data/method_call.json"


val all_call = cpg.call

for(function <- all_call ){
   val method = function.method
   val argument_code = function.argument.where(_.isIdentifier).code
   var argument_lines = ""
   var argument_ids = ""

   for(name <- argument_code){
       val argument = method.local.filter(_.name == name)
       if(!argument.isEmpty){
            // ,,,
            for(arg <- argument)
            {
                argument_lines = argument_lines + arg.lineNumber.toString + " "
                argument_ids = argument_ids + arg.id.toString+ " "
            }

       }
   }

   val result = function.map(node => (node.id,
                                      node.lineNumber,
                                      node.name,
                                      node.code,
                                      argument_lines,
                                      argument_ids,
                                      node.method.id,
                                      node.callee.parameter.id.toList
                                      )).toJsonPretty
   result #>> json_path
}

// ...

val method_call = cpg.method  // ...


val result = method_call.map(node => (node.id,
                                     node.caller.id.l,
                                     )).toJsonPretty
result #>> method_chain_path


// ...


val method = cpg.method

val result2 = method.map(node => (node.id,
                                  node.call.id.l,
                                )).toJsonPretty

result2 #>> method_call_path


