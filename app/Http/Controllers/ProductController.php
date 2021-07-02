<?php

namespace App\Http\Controllers;

use App\Models\Product;
use Illuminate\Http\Request;

class ProductController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        return Product::all();
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {

        $request->validate([
            'name' => 'required',
            'slug' => 'required',
            'price' => 'required'
        ]);

        $product = Product::create($request->all());

        return response()->json([
            'status' => 'success',
            'data' => $product,
            'message' => 'A new product has just been created'
        ], 201);
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        $product = Product::find($id);

        if(is_null($product)){
            return response()->json([
                'status' => 'error',
                'data' => '{}',
                'message' => 'No record found'
            ], 404);
        }else{
            return $product;
        }
         
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        $product = Product::find($id);
        if(is_null($product)){
            return response()->json([
                'status' => 'error',
                'data' => '{}',
                'message' => 'The product that you want to update does not exist'
            ], 404);
        }
        $product->update($request->all());
        return $product;
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        return Product::destroy($id);
    }

    /**
     * Search for a name.
     *
     * @param  str  $name
     * @return \Illuminate\Http\Response
     */
    public function search($name)
    {
        $products = Product::where('name', 'LIKE', '%'.$name.'%')->get();
        if(count($products) == 0){
            return response()->json([
                'status' => 'error',
                'data' => [],
                'message' => 'There is no product name that matches your search string'
            ], 404);
        }
        return $products;
    }
}
